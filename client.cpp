#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <mutex>
#include <condition_variable>
#include <cctype>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>  // For directory creation
#include <fcntl.h> 

#define PORT 8080

using namespace std;

bool logged_in = false;
bool interacting_with_server = false;

mutex mtx;
condition_variable cv;

int direct_listen_port = 0; 
int direct_listen_sock;

SSL_CTX *client_ctx;        // For outgoing client connections (main server, direct initiate)
SSL_CTX *direct_server_ctx; // For incoming direct connections (acts as "server" for direct mode)
SSL *server_ssl;            // For connection to main server

static inline void rtrim(string &s) {
    while (!s.empty() && isspace((unsigned char)s.back())) {
        s.pop_back();
    }
}

void signal_interaction_finished() {
    {
        lock_guard<mutex> lock(mtx);
        interacting_with_server = false;
    }
    cv.notify_one();
}

void init_openssl_library() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_client_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if(!ctx) {
        perror("Unable to create SSL client context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL_CTX* create_direct_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL server context (for direct mode)");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_client_context(SSL_CTX *ctx, const char* ca_cert_file) {
    if (!SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

void configure_direct_server_context(SSL_CTX *ctx, const char* cert_file, const char* key_file) {
    // Load certificate and key for the direct listener
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Direct server private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}

// Thread to listen for direct messages
void direct_listener() {
    direct_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (direct_listen_sock < 0) {
        cerr << "Direct listener socket creation failed\n";
        return;
    }

    int opt = 1;
    setsockopt(direct_listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(0); // ephemeral port

    if (::bind(direct_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "Bind failed for direct listener\n";
        return;
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(direct_listen_sock, (struct sockaddr*)&addr, &addr_len) == -1) {
        cerr << "getsockname failed\n";
        return;
    }

    direct_listen_port = ntohs(addr.sin_port);
    cerr << "Assigned direct port: " << direct_listen_port << endl;

    if (listen(direct_listen_sock, 5) < 0) {
        cerr << "Listen failed for direct listener\n";
        return;
    }

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int new_sock = accept(direct_listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (new_sock < 0) {
            cerr << "Accept failed for direct listener\n";
            continue;
        }

        // Wrap new_sock in SSL for direct connection (server side)
        SSL *direct_ssl = SSL_new(direct_server_ctx);
        SSL_set_fd(direct_ssl, new_sock);
        if (SSL_accept(direct_ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(new_sock);
            SSL_free(direct_ssl);
            continue;
        }

        // Continuously read messages until the other client closes the connection
        char buffer[1024];
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytes = SSL_read(direct_ssl, buffer, 1024);
            if (bytes > 0) {
                cout << "\n[Direct Message Received]: " << buffer << endl;
            } else if (bytes == 0) {
                // Peer closed the connection gracefully
                break;
            } else {
                // An error occurred
                int err = SSL_get_error(direct_ssl, bytes);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    // Connection closed
                    break;
                } else {
                    // Other SSL error
                    ERR_print_errors_fp(stderr);
                    break;
                }
            }
        }

        // Gracefully shutdown the direct SSL connection
        // SSL_shutdown(direct_ssl);
        SSL_free(direct_ssl);
        close(new_sock);
    }
}

void receive_messages() {
    char buffer[1024] = {0};

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = SSL_read(server_ssl, buffer, 1024);
        if (bytes_read <= 0) {
            // Just break, do not free server_ssl here
            break;
        }

        string message(buffer);

        if (message.rfind("SERVER: Receiving file", 0) == 0) {
            // Parse file name
            string file_name = message.substr(message.find("'") + 1);
            file_name = file_name.substr(0, file_name.find("'"));

            cout << "Receiving file: " << file_name << endl;

            // Create file locally
            int fd = open(file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0) {
                cerr << "Error creating file: " << file_name << endl;
                continue;
            }

            while (true) {
                memset(buffer, 0, sizeof(buffer));
                bytes_read = SSL_read(server_ssl, buffer, sizeof(buffer));
                if (bytes_read <= 0 || strcmp(buffer, "END_OF_FILE") == 0) {
                    break; // End of file transmission
                }
                write(fd, buffer, bytes_read);
            }

            close(fd);
            cout << "File received: " << file_name << endl;
        }

        if (message.rfind("SERVER: Online users available for file transfer:", 0) == 0) {
            // Transfer file
            cout << message << endl;

            // Prompt for recipient username
            cout << "Enter recipient username: ";
            string recipient;
            getline(cin, recipient);
            rtrim(recipient);
            SSL_write(server_ssl, recipient.c_str(), recipient.size());

            memset(buffer, 0, sizeof(buffer));
            bytes_read = SSL_read(server_ssl, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                cerr << "Error: Server did not respond.\n";
                continue;
            }
            string response(buffer);
            cout << response << endl;
            if (response.find("not online") != string::npos) continue;

            // Prompt for file name
            cout << "Enter file name to transfer (e.g., a.txt): ";
            string file_name;
            getline(cin, file_name);
            rtrim(file_name);

            // Automatically locate the file in ./<username>/<filename>
            string username = "a"; // Replace this with logic to fetch the current username dynamically if available
            string full_file_path = "./" + username + "/" + file_name;

            // Send file name to the server
            SSL_write(server_ssl, file_name.c_str(), file_name.size());

            memset(buffer, 0, sizeof(buffer));
            bytes_read = SSL_read(server_ssl, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                cerr << "Error: Server did not respond.\n";
                continue;
            }
            cout << string(buffer) << endl;

            // Open the file for reading
            int fd = open(full_file_path.c_str(), O_RDONLY);
            if (fd < 0) {
                cerr << "Error: Unable to open file: " << full_file_path << "\n";
                continue;
            }

            char file_buffer[1024];
            ssize_t bytes_read;

            // Start transferring the file
            cout << "Starting to transfer file: " << file_name << endl;

            while ((bytes_read = read(fd, file_buffer, sizeof(file_buffer))) > 0) {
                if (SSL_write(server_ssl, file_buffer, bytes_read) <= 0) {
                    cerr << "Error: Failed to send file data.\n";
                    break;
                }
                cout << "Sent " << bytes_read << " bytes.\n";  // Debugging log
            }
            close(fd);

            // Signal the end of the file transfer
            string end_signal = "END_OF_FILE";
            SSL_write(server_ssl, end_signal.c_str(), end_signal.size());
            cout << "File transfer completed for: " << file_name << endl;

            // Receive confirmation from the server
            memset(buffer, 0, sizeof(buffer));
            bytes_read = SSL_read(server_ssl, buffer, sizeof(buffer));
            if (bytes_read > 0) {
                cout << string(buffer) << endl;
            }
        }


        if (message.rfind("MSG:", 0) == 0) {
            if (!interacting_with_server) {
                cout << "\n[Message Received]: " << message.substr(4) << endl;
            }
        } else if (message.rfind("SERVER:", 0) == 0) {
            string server_message = message.substr(7);
            cout << "Server: " << server_message << endl;

            if (server_message.find("Logged out successfully.") != string::npos) {
                logged_in = false;
                signal_interaction_finished();
            }
            else if (server_message.find("Registration successful.") != string::npos) {
                signal_interaction_finished();
            }
            else if (server_message.find("Login successful.") != string::npos) {
                logged_in = true;
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                // Send DIRECT_PORT after login
                string port_msg = "DIRECT_PORT:" + to_string(direct_listen_port);
                SSL_write(server_ssl, port_msg.c_str(), port_msg.size());
                signal_interaction_finished();
            }
            else if (server_message.find("Login failed:") != string::npos) {
                signal_interaction_finished();
            }
            else if (server_message.find("Username already exists.") != string::npos) {
                signal_interaction_finished();
            }
            else if (server_message.find("Please enter your username and password") != string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Enter <username> <password>: ";
                string credentials;
                getline(cin, credentials);
                SSL_write(server_ssl, credentials.c_str(), credentials.size());
            }
            else if (server_message.find("Online users:") != string::npos && 
                     server_message.find("direct") == string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send a (relay) message to: ";
                string target_user;
                getline(cin, target_user);
                rtrim(target_user);
                SSL_write(server_ssl, target_user.c_str(), target_user.size());

                memset(buffer, 0, sizeof(buffer));
                int read_count = SSL_read(server_ssl, buffer, 1024);
                if (read_count > 0) {
                    string next_msg(buffer);
                    cout << next_msg << endl;
                    if (next_msg.find("User not found or not online.") != string::npos) {
                        signal_interaction_finished();
                        continue;
                    } else if (next_msg.find("Enter your message:") != string::npos) {
                        cout << "Enter your message: ";
                        string msg;
                        getline(cin, msg);
                        SSL_write(server_ssl, msg.c_str(), msg.size());
                        signal_interaction_finished();
                    } else {
                        signal_interaction_finished();
                    }
                } else {
                    signal_interaction_finished();
                }
            }
            else if (server_message.find("Online users (direct):") != string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send a direct message to: ";
                string target_user;
                getline(cin, target_user);
                rtrim(target_user);
                SSL_write(server_ssl, target_user.c_str(), target_user.size());

                memset(buffer, 0, sizeof(buffer));
                int read_count = SSL_read(server_ssl, buffer, 1024);
                if (read_count > 0) {
                    string info_msg(buffer);
                    cout << info_msg << endl;
                    if (info_msg.find("User not found or not online.") != string::npos) {
                        signal_interaction_finished();
                    } else if (info_msg.find("TARGET_INFO:") != string::npos) {
                        size_t pos = info_msg.find("TARGET_INFO:");
                        string info = info_msg.substr(pos + strlen("TARGET_INFO: "));
                        rtrim(info);
                        string ip = info.substr(0, info.find(' '));
                        string port_str = info.substr(info.find(' ') + 1);
                        rtrim(ip); rtrim(port_str);
                        int target_port = stoi(port_str);

                        cout << "Enter your direct message: ";
                        string direct_msg;
                        getline(cin, direct_msg);

                        // Connect directly with SSL as a client
                        int direct_sock = socket(AF_INET, SOCK_STREAM,0);
                        struct sockaddr_in target_addr;
                        memset(&target_addr,0,sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_port = htons(target_port);
                        inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr);

                        if (connect(direct_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                            cout << "Failed to connect to target user directly.\n";
                            close(direct_sock);
                            signal_interaction_finished();
                            continue;
                        }

                        SSL *direct_ssl = SSL_new(client_ctx);
                        SSL_set_fd(direct_ssl, direct_sock);
                        if (SSL_connect(direct_ssl)<=0) {
                            ERR_print_errors_fp(stderr);
                            close(direct_sock);
                            SSL_free(direct_ssl);
                            cout<<"SSL connect failed to direct user.\n";
                            signal_interaction_finished();
                            continue;
                        }

                        SSL_write(direct_ssl, direct_msg.c_str(), direct_msg.size());
                        cout << "Direct message sent.\n";

                        SSL_shutdown(direct_ssl);
                        SSL_free(direct_ssl);
                        close(direct_sock);
                        signal_interaction_finished();
                    } else {
                        signal_interaction_finished();
                    }
                } else {
                    signal_interaction_finished();
                }
            }
            else if (server_message.find("User not found or not online.") != string::npos) {
                signal_interaction_finished();
            }
            else if (server_message.find("No other users are online.") != string::npos) {
                signal_interaction_finished();
            }
            else if (server_message.find("Invalid option.") != string::npos) {
                signal_interaction_finished();
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        cerr << "Usage: " << argv[0] << " <ca.crt> <client_server.crt> <client_server.key>\n";
        return -1;
    }

    init_openssl_library();
    client_ctx = create_client_context();
    configure_client_context(client_ctx, argv[1]);

    direct_server_ctx = create_direct_server_context();
    configure_direct_server_context(direct_server_ctx, argv[2], argv[3]);

    // Start direct listener thread
    thread dl(direct_listener);
    dl.detach();

    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation error\n";
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cerr << "Invalid address / Address not supported\n";
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection failed\n";
        return -1;
    }

    server_ssl = SSL_new(client_ctx);
    SSL_set_fd(server_ssl, sock);
    if (SSL_connect(server_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sock);
        SSL_free(server_ssl);
        return -1;
    }

    // Start thread to handle receiving messages
    thread listener(receive_messages);
    listener.detach();

    while (true) {
        {
            unique_lock<mutex> lock(mtx);
            while (interacting_with_server) {
                cv.wait(lock);
            }
        }

        cout << "\nSelect a service:\n";
        if (!logged_in) {
            cout << "1. Register\n";
            cout << "2. Login\n";
            cout << "3. Exit\n";
        } else {
            cout << "1. Logout\n";
            cout << "2. Send Message (Relay mode)\n";
            cout << "3. Send Message (Direct mode)\n";
            cout << "4. Transfer file\n";
            cout << "5. Exit\n";
        }

        string choice;
        getline(cin, choice);
        rtrim(choice);
        SSL_write(server_ssl, choice.c_str(), choice.size());

        if ((!logged_in && choice == "3") || (logged_in && choice == "5")) {
            cout << "Exiting...\n";
            break;
        }

        if (!logged_in) {
            if (choice == "1" || choice == "2") {
                lock_guard<mutex> lock(mtx);
                interacting_with_server = true;
            }
        } else {
            if (choice == "1" || choice == "2" || choice == "3" || choice == "4") {
                lock_guard<mutex> lock(mtx);
                interacting_with_server = true;
            }

        }
    }

    // Properly shut down and free resources once main loop ends
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(direct_server_ctx);
    cleanup_openssl();
    return 0;
}
