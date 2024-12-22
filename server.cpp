#include <iostream>
#include <string>
#include <unordered_map>
#include <cstring>
#include <queue>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cctype>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>  // Include for directory creation
#include <sys/types.h>
#include <sys/stat.h>  // For directory creation
#include <fcntl.h> 

#define PORT 8080
#define MAX_WORKERS 10
#define MAX_QUEUE_SIZE 100

using namespace std;

struct UserInfo {
    string password;
    bool logged_in = false;
    int sock = -1;
    string ip;
    int direct_port = -1;
};

unordered_map<string, UserInfo> users;         
unordered_map<string, int> logged_in_clients;
queue<int> client_queue;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

// SSL Globals (server)
SSL_CTX *server_ctx;

// Global map for user->SSL*
unordered_map<string, SSL*> user_ssl_map;

static inline void rtrim(string &s) {
    while (!s.empty() && isspace((unsigned char)s.back())) {
        s.pop_back();
    }
}

void init_openssl_library() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_server_context(SSL_CTX *ctx, const char* cert_file, const char* key_file) {
    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Load server private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

void handle_client_ssl(SSL *ssl) {
    char buffer[1024] = {0};
    bool is_logged_in = false;
    string current_user;

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int client_socket = SSL_get_fd(ssl);
    getpeername(client_socket, (struct sockaddr*)&addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    while (true) {
        memset(buffer,0,sizeof(buffer));
        int bytes_read = SSL_read(ssl, buffer, 1024);
        if (bytes_read <= 0) {
            // Connection closed
            if (is_logged_in) {
                pthread_mutex_lock(&queue_mutex);
                users[current_user].logged_in = false;
                logged_in_clients.erase(current_user);
                // Remove from user_ssl_map
                user_ssl_map.erase(current_user);
                pthread_mutex_unlock(&queue_mutex);
            }
            close(client_socket);
            SSL_free(ssl);
            break;
        }

        string message(buffer);
        message = message.substr(0, message.find("\n"));
        rtrim(message);

        if (is_logged_in && message.rfind("DIRECT_PORT:", 0) == 0) {
            // Set the direct port
            int port = stoi(message.substr(strlen("DIRECT_PORT:")));
            pthread_mutex_lock(&queue_mutex);
            users[current_user].direct_port = port;
            pthread_mutex_unlock(&queue_mutex);
            continue;
        }

        if (!is_logged_in) {
            // Not logged in states
            if (message == "1") { // Register
                string response = "SERVER: Please enter your username and password separated by a space (e.g., user pass): ";
                SSL_write(ssl, response.c_str(), response.size());

                memset(buffer,0,sizeof(buffer));
                bytes_read = SSL_read(ssl, buffer, 1024);
                if (bytes_read<=0) break;

                string credentials(buffer);
                credentials = credentials.substr(0,credentials.find("\n"));
                rtrim(credentials);
                string username = credentials.substr(0, credentials.find(' '));
                string password = credentials.substr(credentials.find(' ')+1);

                pthread_mutex_lock(&queue_mutex);
                auto create_user_directory = [](const string &username) {
                    struct stat st;
                    if (stat(username.c_str(), &st) == -1) {
                        mkdir(username.c_str(), 0700);
                    }
                };

                if (users.find(username) != users.end() && users[username].password != "") {
                    response = "SERVER: Username already exists.\n";
                } else {
                    users[username].password = password;
                    users[username].logged_in = false;
                    create_user_directory(username);  // Create a directory for the user
                    response = "SERVER: Registration successful.\n";
                    cout << "Register Success: " << username << " " << password << endl;
                }
                pthread_mutex_unlock(&queue_mutex);

                SSL_write(ssl, response.c_str(), response.size());

            } else if (message == "2") { // Login
                string response="SERVER: Please enter your username and password separated by a space (e.g., user pass): ";
                SSL_write(ssl,response.c_str(),response.size());

                memset(buffer,0,sizeof(buffer));
                bytes_read=SSL_read(ssl,buffer,1024);
                if (bytes_read<=0) break;

                string credentials(buffer);
                credentials = credentials.substr(0,credentials.find("\n"));
                rtrim(credentials);
                string username = credentials.substr(0, credentials.find(' '));
                string password = credentials.substr(credentials.find(' ')+1);

                pthread_mutex_lock(&queue_mutex);
                if (users.find(username)==users.end()||users[username].password!=password) {
                    response="SERVER: Login failed: incorrect username or password.\n";
                } else if (users[username].logged_in) {
                    response="SERVER: Login failed: user already logged in.\n";
                } else {
                    is_logged_in=true;
                    current_user=username;
                    users[username].logged_in=true;
                    users[username].sock=client_socket;
                    users[username].ip=string(client_ip);
                    logged_in_clients[username]=client_socket;
                    // Store SSL pointer for this user
                    user_ssl_map[username] = ssl;
                    response="SERVER: Login successful.\n";
                    cout << "Login Success : " << username << endl;
                }
                pthread_mutex_unlock(&queue_mutex);

                SSL_write(ssl,response.c_str(),response.size());

            } else if (message=="3") { // Exit
                string response="SERVER: Exiting...\n";
                SSL_write(ssl,response.c_str(),response.size());
                break;

            } else {
                string response="SERVER: Invalid option.\n";
                SSL_write(ssl,response.c_str(),response.size());
            }

        } else {
            // Logged in
            if (message=="1") { // Logout
                pthread_mutex_lock(&queue_mutex);
                users[current_user].logged_in=false;
                logged_in_clients.erase(current_user);
                user_ssl_map.erase(current_user);
                pthread_mutex_unlock(&queue_mutex);

                current_user.clear();
                is_logged_in=false;
                string response="SERVER: Logged out successfully.\n";
                SSL_write(ssl,response.c_str(),response.size());

            } else if (message=="2") { // Relay mode
                pthread_mutex_lock(&queue_mutex);
                string response="SERVER: Online users:\n";
                for (auto &u: logged_in_clients) {
                    if (u.first!=current_user) {
                        response+=u.first+"\n";
                    }
                }
                pthread_mutex_unlock(&queue_mutex);

                if (response=="SERVER: Online users:\n") {
                    response="SERVER: No other users are online.\n";
                    SSL_write(ssl,response.c_str(),response.size());
                    continue;
                }

                SSL_write(ssl,response.c_str(),response.size());

                memset(buffer,0,sizeof(buffer));
                bytes_read=SSL_read(ssl,buffer,1024);
                if (bytes_read<=0) break;

                {
                    string target_user(buffer);
                    target_user=target_user.substr(0,target_user.find("\n"));
                    rtrim(target_user);

                    pthread_mutex_lock(&queue_mutex);
                    if (users.find(target_user)==users.end() || !users[target_user].logged_in) {
                        pthread_mutex_unlock(&queue_mutex);
                        string err="SERVER: User not found or not online.\n";
                        SSL_write(ssl,err.c_str(),err.size());
                        continue;
                    }
                    pthread_mutex_unlock(&queue_mutex);

                    string prompt="SERVER: Enter your message: ";
                    SSL_write(ssl,prompt.c_str(),prompt.size());

                    memset(buffer,0,sizeof(buffer));
                    bytes_read=SSL_read(ssl,buffer,1024);
                    if (bytes_read<=0) break;

                    string user_msg(buffer);
                    user_msg=user_msg.substr(0,user_msg.find("\n"));
                    rtrim(user_msg);
                    string final_msg="MSG: "+current_user+": "+user_msg;
                    cout << current_user << " send message to " << target_user << " : " << user_msg << endl;

                    // Send message to target user's SSL session
                    pthread_mutex_lock(&queue_mutex);
                    if (user_ssl_map.find(target_user)!=user_ssl_map.end()) {
                        SSL *target_ssl = user_ssl_map[target_user];
                        SSL_write(target_ssl, final_msg.c_str(), final_msg.size());
                    } else {
                        string err = "SERVER: Couldn't find target user's SSL session.\n";
                        SSL_write(ssl, err.c_str(), err.size());
                    }
                    pthread_mutex_unlock(&queue_mutex);
                }

            } else if (message=="3") { // Direct mode
                pthread_mutex_lock(&queue_mutex);
                string response="SERVER: Online users (direct):\n";
                for (auto &u:users) {
                    if (u.first!=current_user && u.second.logged_in && u.second.direct_port!=-1) {
                        response+=u.first+"\n";
                    }
                }
                pthread_mutex_unlock(&queue_mutex);

                if (response=="SERVER: Online users (direct):\n") {
                    response="SERVER: No other users are online.\n";
                    SSL_write(ssl,response.c_str(),response.size());
                    continue;
                }

                SSL_write(ssl,response.c_str(),response.size());

                memset(buffer,0,sizeof(buffer));
                bytes_read=SSL_read(ssl,buffer,1024);
                if (bytes_read<=0) break;
                {
                    string target_user(buffer);
                    target_user=target_user.substr(0,target_user.find("\n"));
                    rtrim(target_user);
                    pthread_mutex_lock(&queue_mutex);
                    if (users.find(target_user)==users.end()||!users[target_user].logged_in||users[target_user].direct_port==-1) {
                        pthread_mutex_unlock(&queue_mutex);
                        string err="SERVER: User not found or not online.\n";
                        SSL_write(ssl,err.c_str(),err.size());
                        continue;
                    }
                    string ip=users[target_user].ip;
                    int dport=users[target_user].direct_port;
                    pthread_mutex_unlock(&queue_mutex);

                    cout << "[DEBUG] Direct mode: " << current_user << " -> " << target_user << " IP=" << ip << " PORT=" << dport << endl;

                    string info="SERVER:TARGET_INFO: "+ip+" "+to_string(dport)+"\n";
                    SSL_write(ssl,info.c_str(),info.size());
                }

            } else if (message == "4") { // Transfer file
                pthread_mutex_lock(&queue_mutex);

                // Send the list of online users
                string response = "SERVER: Online users available for file transfer:\n";
                for (const auto& user : users) {
                    if (user.first != current_user && user.second.logged_in) {
                        response += user.first + "\n";
                    }
                }
                pthread_mutex_unlock(&queue_mutex);

                if (response == "SERVER: Online users available for file transfer:\n") {
                    response = "SERVER: No other users are online.\n";
                    SSL_write(ssl, response.c_str(), response.size());
                    continue;
                }
                SSL_write(ssl, response.c_str(), response.size());

                // Receive recipient username
                memset(buffer, 0, sizeof(buffer));
                int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
                if (bytes_read <= 0) {
                    cerr << "Error: Failed to read recipient username.\n";
                    continue;
                }
                string recipient(buffer);
                rtrim(recipient);

                pthread_mutex_lock(&queue_mutex);
                if (users.find(recipient) == users.end() || !users[recipient].logged_in) {
                    pthread_mutex_unlock(&queue_mutex);
                    response = "SERVER: User not found or not online.\n";
                    SSL_write(ssl, response.c_str(), response.size());
                    continue;
                }
                pthread_mutex_unlock(&queue_mutex);

                // Confirm recipient to the sender
                response = "SERVER: Selected user: " + recipient + ".\n";
                SSL_write(ssl, response.c_str(), response.size());

                // Ask for the file name
                response = "SERVER: Enter the file name to transfer:";
                SSL_write(ssl, response.c_str(), response.size());

                memset(buffer, 0, sizeof(buffer));
                bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
                if (bytes_read <= 0) {
                    cerr << "Error: Failed to read file name.\n";
                    continue;
                }
                string file_name(buffer);
                rtrim(file_name);

                // Create recipient's file
                string file_path = "./" + recipient + "/" + file_name;
                int fd = open(file_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (fd < 0) {
                    cerr << "Error creating file for recipient: " << file_path << endl;
                    response = "SERVER: Error saving file for recipient.\n";
                    SSL_write(ssl, response.c_str(), response.size());
                    continue;
                }

                // Notify sender to start transferring file data
                response = "SERVER: Ready to receive file data.\n";
                SSL_write(ssl, response.c_str(), response.size());

                // Receive file data
                char buffer[1024];
                while (true) {
                    cout << "here" << endl;
                    memset(buffer, 0, sizeof(buffer));
                    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
                    if (bytes_read <= 0) {
                        cerr << "Error: SSL_read failed during file transfer.\n";
                        break;
                    }
                    if (strcmp(buffer, "END_OF_FILE") == 0) {
                        cout << "End of file transfer detected.\n";
                        break;
                    }
                    if (write(fd, buffer, bytes_read) < 0) {
                        cerr << "Error: Failed to write data to file.\n";
                        break;
                    }
                    cout << "Server: Received " << bytes_read << " bytes.\n";  // Debugging log
                }
                close(fd);
                cout << "File reception completed successfully.\n";



                // Notify the recipient
                pthread_mutex_lock(&queue_mutex);
                SSL* recipient_ssl = user_ssl_map[recipient];
                pthread_mutex_unlock(&queue_mutex);

                string notify = "SERVER: File '" + file_name + "' has been received and saved in your directory.\n";
                SSL_write(recipient_ssl, notify.c_str(), notify.size());


                // Notify the sender
                response = "SERVER: File transfer to " + recipient + " completed.\n";
                SSL_write(ssl, response.c_str(), response.size());

            }




            else if (message=="5") { // Exit
                string response="SERVER: Exiting...\n";
                SSL_write(ssl,response.c_str(),response.size());
                if (is_logged_in) {
                    pthread_mutex_lock(&queue_mutex);
                    users[current_user].logged_in=false;
                    logged_in_clients.erase(current_user);
                    user_ssl_map.erase(current_user);
                    pthread_mutex_unlock(&queue_mutex);
                }
                break;
            } else {
                string response="SERVER: Invalid option.\n";
                SSL_write(ssl,response.c_str(),response.size());
            }
        }
    }

    close(client_socket);
}

void *worker_thread(void *arg) {
    while (true) {
        pthread_mutex_lock(&queue_mutex);

        while (client_queue.empty()) {
            pthread_cond_wait(&condition_var,&queue_mutex);
        }

        int client_socket = client_queue.front();
        client_queue.pop();

        pthread_mutex_unlock(&queue_mutex);

        // Wrap socket with SSL
        SSL *ssl = SSL_new(server_ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            SSL_free(ssl);
            continue;
        }

        // Now handle the client with SSL
        handle_client_ssl(ssl);
    }
    return nullptr;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <server.crt> <server.key>\n";
        return -1;
    }

    init_openssl_library();
    server_ctx = create_server_context();
    configure_server_context(server_ctx, argv[1], argv[2]);

    int server_fd;
    struct sockaddr_in address;
    int opt=1;
    int addrlen=sizeof(address);

    if ((server_fd=socket(AF_INET, SOCK_STREAM,0))==0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt))) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family=AF_INET;
    address.sin_addr.s_addr=INADDR_ANY;
    address.sin_port=htons(PORT);

    if (::bind(server_fd,(struct sockaddr*)&address,sizeof(address))<0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd,MAX_QUEUE_SIZE)<0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    cout<<"Server started on port "<<PORT<<"...\n";

    pthread_t thread_pool[MAX_WORKERS];
    for (int i=0;i<MAX_WORKERS;++i) {
        pthread_create(&thread_pool[i],nullptr,worker_thread,nullptr);
    }

    while (true) {
        int client_socket=accept(server_fd,(struct sockaddr*)&address,(socklen_t*)&addrlen);
        if (client_socket<0) {
            perror("Accept failed");
            continue;
        }

        pthread_mutex_lock(&queue_mutex);
        client_queue.push(client_socket);
        pthread_cond_signal(&condition_var);
        pthread_mutex_unlock(&queue_mutex);
    }

    close(server_fd);
    SSL_CTX_free(server_ctx);
    cleanup_openssl();
    return 0;
}
