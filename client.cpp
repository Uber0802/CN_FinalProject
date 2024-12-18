// client.cpp
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

#define PORT 8080

using namespace std;

bool logged_in = false;
bool interacting_with_server = false;

mutex mtx;
condition_variable cv;

int direct_listen_port = 0; 
int direct_listen_sock;

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

// Thread to listen for direct messages (with ephemeral port)
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
    // Port 0: Let OS assign an available port
    addr.sin_port = htons(0);

    if (::bind(direct_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "Bind failed for direct listener\n";
        return;
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(direct_listen_sock, (struct sockaddr*)&addr, &addr_len) == -1) {
        cerr << "getsockname failed\n";
        return;
    }

    int assigned_port = ntohs(addr.sin_port);
    direct_listen_port = assigned_port;
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

        char buffer[1024] = {0};
        int bytes = read(new_sock, buffer, 1024);
        if (bytes > 0) {
            cout << "\n[Direct Message Received]: " << buffer << endl;
        }
        close(new_sock);
    }
}

void receive_messages(int sock) {
    char buffer[1024] = {0};

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(sock, buffer, 1024);
        if (bytes_read <= 0) {
            close(sock);
            break;
        }

        string message(buffer);

        if (message.rfind("MSG:", 0) == 0) {
            // Relay message
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
                // After login, send our assigned direct port to the server
                string port_msg = "DIRECT_PORT:" + to_string(direct_listen_port);
                send(sock, port_msg.c_str(), port_msg.size(), 0);
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
                string credentials;
                cout << "Enter <username> <password>: ";
                getline(cin, credentials);
                send(sock, credentials.c_str(), credentials.size(), 0);
            }
            else if (server_message.find("Online users:") != string::npos && 
                     server_message.find("direct") == string::npos) {
                // Relay mode sending
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send a (relay) message to: ";
                string target_user;
                getline(cin, target_user);
                rtrim(target_user);
                send(sock, target_user.c_str(), target_user.size(), 0);

                memset(buffer, 0, sizeof(buffer));
                int read_count = read(sock, buffer, 1024);
                if (read_count > 0) {
                    string next_msg(buffer);
                    cout << next_msg << endl;
                    if (next_msg.find("User not found or not online.") != string::npos) {
                        signal_interaction_finished();
                        continue;
                    } else if (next_msg.find("Enter your message:") != string::npos) {
                        string msg;
                        getline(cin, msg);
                        send(sock, msg.c_str(), msg.size(), 0);
                        signal_interaction_finished();
                    } else {
                        signal_interaction_finished();
                    }
                } else {
                    signal_interaction_finished();
                }
            }
            else if (server_message.find("Online users (direct):") != string::npos) {
                // Direct mode sending
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send a direct message to: ";
                string target_user;
                getline(cin, target_user);
                rtrim(target_user);
                send(sock, target_user.c_str(), target_user.size(), 0);

                memset(buffer, 0, sizeof(buffer));
                int read_count = read(sock, buffer, 1024);
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

                        int direct_sock = socket(AF_INET, SOCK_STREAM,0);
                        struct sockaddr_in target_addr;
                        memset(&target_addr,0,sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_port = htons(target_port);
                        inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr);

                        if (connect(direct_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                            cout << "Failed to connect to target user directly.\n";
                        } else {
                            send(direct_sock, direct_msg.c_str(), direct_msg.size(), 0);
                            close(direct_sock);
                            cout << "Direct message sent.\n";
                        }
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

int main() {
    // Start direct listener thread (assigns ephemeral port)
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

    thread listener(receive_messages, sock);
    listener.detach();

    while (true) {
        {
            unique_lock<mutex> lock(mtx);
            cv.wait(lock, [] { return !interacting_with_server; });
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
            cout << "4. Exit\n";
        }

        string choice;
        getline(cin, choice);
        rtrim(choice);
        send(sock, choice.c_str(), choice.size(), 0);

        if ((!logged_in && choice == "3") || (logged_in && choice == "4")) {
            cout << "Exiting...\n";
            break;
        }

        if (!logged_in) {
            if (choice == "1" || choice == "2") {
                lock_guard<mutex> lock(mtx);
                interacting_with_server = true;
            }
        } else {
            if (choice == "1" || choice == "2" || choice == "3") {
                lock_guard<mutex> lock(mtx);
                interacting_with_server = true;
            }
        }
    }

    close(sock);
    return 0;
}
