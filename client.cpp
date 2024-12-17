#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <mutex>
#include <condition_variable>

#define PORT 8080

using namespace std;

bool logged_in = false;
bool interacting_with_server = false;

// Condition variable to coordinate printing the menu
mutex mtx;
condition_variable cv;

void signal_interaction_finished() {
    {
        lock_guard<mutex> lock(mtx);
        interacting_with_server = false;
    }
    cv.notify_one();
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

        // Check for relayed client-to-client messages
        if (message.rfind("MSG:", 0) == 0) {
            if (!interacting_with_server) {
                cout << "\n[Message Received]: " << message.substr(4) << endl;
            }
        }
        // Server messages
        else if (message.rfind("SERVER:", 0) == 0) {
            string server_message = message.substr(7); // remove "SERVER: "
            cout << "Server: " << server_message << endl;

            // Decide how to handle server messages
            if (server_message.find("Logged out successfully.") != string::npos) {
                logged_in = false;
                signal_interaction_finished();
            }
            else if (server_message.find("Registration successful.") != string::npos) {
                signal_interaction_finished();
            }
            else if (server_message.find("Login successful.") != string::npos) {
                logged_in = true;
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
            else if (server_message.find("Online users:") != string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send a message to: ";
                string target_user;
                getline(cin, target_user);
                send(sock, target_user.c_str(), target_user.size(), 0);

                // Read server’s next response
                memset(buffer, 0, sizeof(buffer));
                int read_count = read(sock, buffer, 1024);
                if (read_count > 0) {
                    string next_message(buffer);
                    cout << next_message << endl; 

                    if (next_message.find("User not found or not online.") != string::npos) {
                        signal_interaction_finished();
                        continue;
                    }
                    else if (next_message.find("Enter your message:") != string::npos) {
                        string msg;
                        getline(cin, msg);
                        send(sock, msg.c_str(), msg.size(), 0);
                        signal_interaction_finished();
                    }
                    else {
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
            else if (server_message.find("You must log in to send messages.") != string::npos) {
                signal_interaction_finished();
            }
        }
    }
}

int main() {
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
            // Modified: no “Register” after log in
            cout << "1. Logout\n";
            cout << "2. Send Message\n";
            cout << "3. Exit\n";
        }

        string choice;
        getline(cin, choice);
        send(sock, choice.c_str(), choice.size(), 0);

        // If user selects Exit
        if ((!logged_in && choice == "3") || (logged_in && choice == "3")) {
            // Notice that if logged_in==true, now "3" means "Exit"
            cout << "Exiting...\n";
            break;
        }

        // If the user is logged out: 1=Register, 2=Login
        // If the user is logged in: 1=Logout, 2=SendMessage
        // We set interacting_with_server if it’s an action that triggers server prompts
        if (!logged_in) {
            // Register = "1", Login = "2"
            if (choice == "1" || choice == "2") {
                lock_guard<mutex> lock(mtx);
                interacting_with_server = true;
            }
        } else {
            // Logout = "1", Send Message = "2"
            if (choice == "1" || choice == "2") {
                lock_guard<mutex> lock(mtx);
                interacting_with_server = true;
            }
        }
    }

    close(sock);
    return 0;
}
