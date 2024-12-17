// client.cpp
#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080

using namespace std;

bool logged_in = false;
bool interacting_with_server = false;

// Include threading and synchronization
#include <mutex>
#include <condition_variable>
mutex mtx;
condition_variable cv;

// Utility function for the receive thread to let the main loop know: 
// "Done interacting with the server — it's safe to show the menu again."
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
            // Server closed connection or error
            close(sock);
            break;
        }

        string message(buffer);

        if (message.rfind("MSG:", 0) == 0) {
            // Relay (private) message from another client
            // If desired, we can block it if interacting_with_server == true
            if (!interacting_with_server) {
                cout << "\n[Message Received]: " << message.substr(4) << endl;
            }
        } 
        else if (message.rfind("SERVER:", 0) == 0) {
            // Server-side messages / prompts
            string server_message = message.substr(7); // Remove "SERVER: "

            cout << "Server: " << server_message << endl;

            // Check for triggers:
            if (server_message.find("Logged out successfully.") != string::npos) {
                logged_in = false;
                signal_interaction_finished();
            }
            else if (server_message.find("Registration successful.") != string::npos) {
                // Done with registration interaction
                signal_interaction_finished();
            }
            else if (server_message.find("Login successful.") != string::npos) {
                logged_in = true;
                signal_interaction_finished();
            }
            else if (server_message.find("Login failed: incorrect username or password.") != string::npos) {
                // The server gave a failure message
                signal_interaction_finished();
            }
            else if (server_message.find("Username already exists.") != string::npos) {
                // Registration failed
                signal_interaction_finished();
            }
            else if (server_message.find("Please enter your username and password") != string::npos) {
                // Server is requesting credentials — let's get them
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }

                string credentials;
                cout << "Enter <username> <password>: ";
                getline(cin, credentials);
                send(sock, credentials.c_str(), credentials.size(), 0);

                // We'll wait for “Registration successful” or “Login successful” in the receive thread
            }
            else if (server_message.find("Online users:") != string::npos) {
                // The server wants us to pick a target user — mark interacting true
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send a message to: ";
                string target_user;
                getline(cin, target_user);
                send(sock, target_user.c_str(), target_user.size(), 0);

                // Wait for server prompt to send the actual message
                memset(buffer, 0, sizeof(buffer));
                int read_count = read(sock, buffer, 1024);
                if (read_count > 0) {
                    string prompt(buffer);
                    cout << prompt << endl;  // e.g. "SERVER: Enter your message:"
                    string message_to_send;
                    getline(cin, message_to_send);
                    send(sock, message_to_send.c_str(), message_to_send.size(), 0);
                }
                signal_interaction_finished();
            }
            // If server says "Invalid option." or "No other users are online." — no user input
            // needed afterwards, so we can stay unlocked. But it's okay if the code stands as is.
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

    // Start a thread to handle receiving messages from server
    thread listener(receive_messages, sock);
    listener.detach();

    while (true) {
        // Wait until we're not interacting
        {
            unique_lock<mutex> lock(mtx);
            cv.wait(lock, [] { return !interacting_with_server; });
        }

        // Print the main menu
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

        // Send the choice to the server
        send(sock, choice.c_str(), choice.size(), 0);

        // If user wants to exit
        if ((!logged_in && choice == "3") || (logged_in && choice == "4")) {
            cout << "Exiting...\n";
            break;
        }

        // If the choice is one that leads to a server prompt (Register / Login / Logout / SendMessage)
        // then immediately set interacting_with_server so we don’t reprint the menu prematurely.
        if ((choice == "1" && !logged_in) ||  // Register
            (choice == "2" && !logged_in) ||  // Login
            (choice == "2" && logged_in)  ||  // Logout
            (choice == "3" && logged_in))     // Send Message
        {
            lock_guard<mutex> lock(mtx);
            interacting_with_server = true;
        }
    }

    close(sock);
    return 0;
}
