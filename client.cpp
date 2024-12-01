#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080

using namespace std; // Explicitly include the std namespace

bool logged_in = false;

void receive_messages(int sock) {
    char buffer[1024] = {0};

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(sock, buffer, 1024);
        if (bytes_read > 0) {
            string message(buffer);

            if (message.rfind("MSG:", 0) == 0) { // Relayed message from another client
                cout << "\n[Message Received]: " << message.substr(4) << endl;
            } else if (message.rfind("SERVER:", 0) == 0) { // Server interaction messages
                string server_message = message.substr(7);
                cout << "Server: " << server_message << endl;

                if (server_message.find("Logged out successfully.") != string::npos) {
                    logged_in = false;
                } else if (server_message.find("Please enter your username and password") != string::npos) {
                    string credentials;
                    cout << "Enter <username> <password>: ";
                    getline(cin, credentials);
                    send(sock, credentials.c_str(), credentials.size(), 0);
                } else if (server_message.find("Online users:") != string::npos) {
                    cout << "Choose a user to send a message to: ";
                    string target_user;
                    getline(cin, target_user);
                    send(sock, target_user.c_str(), target_user.size(), 0);

                    // Wait for server prompt to send the message
                    memset(buffer, 0, sizeof(buffer));
                    bytes_read = read(sock, buffer, 1024);
                    if (bytes_read > 0) {
                        string response(buffer);
                        cout << response << endl;

                        string message_to_send;
                        cout << "Enter your message: ";
                        getline(cin, message_to_send);
                        send(sock, message_to_send.c_str(), message_to_send.size(), 0);
                    }
                }
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

    // Start a thread to handle receiving messages
    thread listener(receive_messages, sock);
    listener.detach();

    while (true) {
        cout << "\nSelect a service:\n";
        if (!logged_in) {
            cout << "1. Register\n";
            cout << "2. Login\n";
            cout << "3. Exit\n";
        } else {
            cout << "1. Register\n";
            cout << "2. Logout\n";
            cout << "3. Send Message\n";
            cout << "4. Exit\n";
        }

        string choice;
        getline(cin, choice);

        send(sock, choice.c_str(), choice.size(), 0);

        if (choice == "3" && !logged_in) { // Exit when not logged in
            cout << "Exiting...\n";
            break;
        } else if (choice == "4" && logged_in) { // Exit when logged in
            cout << "Exiting...\n";
            break;
        }
    }

    close(sock);
    return 0;
}
