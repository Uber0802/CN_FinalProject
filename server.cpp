// server.cpp
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstring>
#include <queue>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define MAX_WORKERS 10
#define MAX_QUEUE_SIZE 100

using namespace std;

// Global variables for users and client states
unordered_map<string, string> users;          // username -> password
unordered_map<string, int> logged_in_clients; // username -> socket
queue<int> client_queue;                      // queue of incoming client sockets
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

// Function to handle a single client connection
void handle_client(int client_socket) {
    char buffer[1024] = {0};
    bool is_logged_in = false;
    string current_user;

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(client_socket, buffer, 1024);

        // Client disconnected or read error
        if (bytes_read <= 0) {
            if (is_logged_in) {
                pthread_mutex_lock(&queue_mutex);
                logged_in_clients.erase(current_user); 
                pthread_mutex_unlock(&queue_mutex);
            }
            close(client_socket);
            break;
        }

        string message(buffer);
        // Strip trailing newline if present
        message = message.substr(0, message.find("\n"));

        if (message == "1") {
            // Register
            string response = "SERVER: Please enter your username and password separated by a space (e.g., user pass): ";
            send(client_socket, response.c_str(), response.size(), 0);

            memset(buffer, 0, sizeof(buffer));
            bytes_read = read(client_socket, buffer, 1024);
            if (bytes_read <= 0) break;

            string credentials(buffer);
            string username = credentials.substr(0, credentials.find(' '));
            string password = credentials.substr(credentials.find(' ') + 1);

            pthread_mutex_lock(&queue_mutex);
            if (users.find(username) != users.end()) {
                response = "SERVER: Username already exists.\n";
            } else {
                users[username] = password;
                response = "SERVER: Registration successful.\n";
            }
            pthread_mutex_unlock(&queue_mutex);

            send(client_socket, response.c_str(), response.size(), 0);

        } else if (message == "2") {
            // Login or Logout
            if (!is_logged_in) {
                // Login
                string response = "SERVER: Please enter your username and password separated by a space (e.g., user pass): ";
                send(client_socket, response.c_str(), response.size(), 0);

                memset(buffer, 0, sizeof(buffer));
                bytes_read = read(client_socket, buffer, 1024);
                if (bytes_read <= 0) break;

                string credentials(buffer);
                string username = credentials.substr(0, credentials.find(' '));
                string password = credentials.substr(credentials.find(' ') + 1);

                pthread_mutex_lock(&queue_mutex);
                if (users.find(username) == users.end() || users[username] != password) {
                    response = "SERVER: Login failed: incorrect username or password.\n";
                } else if (logged_in_clients.find(username) != logged_in_clients.end()) {
                    response = "SERVER: Login failed: user already logged in.\n";
                } else {
                    is_logged_in = true;
                    current_user = username;
                    logged_in_clients[username] = client_socket;
                    response = "SERVER: Login successful.\n";
                }
                pthread_mutex_unlock(&queue_mutex);

                send(client_socket, response.c_str(), response.size(), 0);

            } else {
                // Logout
                is_logged_in = false;
                pthread_mutex_lock(&queue_mutex);
                logged_in_clients.erase(current_user);
                pthread_mutex_unlock(&queue_mutex);
                current_user.clear();
                string response = "SERVER: Logged out successfully.\n";
                send(client_socket, response.c_str(), response.size(), 0);
            }

        } else if (message == "3") {
            // Send Message
            if (!is_logged_in) {
                string response = "SERVER: You must log in to send messages.\n";
                send(client_socket, response.c_str(), response.size(), 0);
                continue;
            }

            // List online users
            pthread_mutex_lock(&queue_mutex);
            string response = "SERVER: Online users:\n";
            for (const auto &pair : logged_in_clients) {
                if (pair.first != current_user) {
                    response += pair.first + "\n";
                }
            }
            pthread_mutex_unlock(&queue_mutex);

            // If there are no other users online
            if (response == "SERVER: Online users:\n") {
                response = "SERVER: No other users are online.\n";
                send(client_socket, response.c_str(), response.size(), 0);
                continue;
            }

            send(client_socket, response.c_str(), response.size(), 0);

            // Read the target username
            memset(buffer, 0, sizeof(buffer));
            bytes_read = read(client_socket, buffer, 1024);
            if (bytes_read <= 0) break;

            string target_user(buffer);
            target_user = target_user.substr(0, target_user.find("\n"));

            pthread_mutex_lock(&queue_mutex);
            if (logged_in_clients.find(target_user) == logged_in_clients.end()) {
                response = "SERVER: User not found or not online.\n";
                pthread_mutex_unlock(&queue_mutex);
                send(client_socket, response.c_str(), response.size(), 0);
                continue;
            }
            int target_socket = logged_in_clients[target_user];
            pthread_mutex_unlock(&queue_mutex);

            // Prompt the sender for the actual message
            response = "SERVER: Enter your message: ";
            send(client_socket, response.c_str(), response.size(), 0);

            memset(buffer, 0, sizeof(buffer));
            bytes_read = read(client_socket, buffer, 1024);
            if (bytes_read <= 0) break;

            string message_to_send(buffer);
            message_to_send = "MSG: " + current_user + ": " + message_to_send;
            // Relay to the target user
            send(target_socket, message_to_send.c_str(), message_to_send.size(), 0);

        } else if (message == "4") {
            // Exit
            string response = "SERVER: Exiting...\n";
            send(client_socket, response.c_str(), response.size(), 0);
            if (is_logged_in) {
                pthread_mutex_lock(&queue_mutex);
                logged_in_clients.erase(current_user);
                pthread_mutex_unlock(&queue_mutex);
            }
            break;

        } else {
            // Invalid Option
            string response = "SERVER: Invalid option.\n";
            send(client_socket, response.c_str(), response.size(), 0);
        }
    }

    close(client_socket);
}

// Worker thread function
void *worker_thread(void *arg) {
    while (true) {
        pthread_mutex_lock(&queue_mutex);

        while (client_queue.empty()) {
            pthread_cond_wait(&condition_var, &queue_mutex);
        }

        int client_socket = client_queue.front();
        client_queue.pop();

        pthread_mutex_unlock(&queue_mutex);

        // Handle this client
        handle_client(client_socket);
    }
    return nullptr;
}

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Create server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Reuse address
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    address.sin_port = htons(PORT);

    if (::bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_QUEUE_SIZE) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    cout << "Server started on port " << PORT << "...\n";

    // Create a pool of worker threads
    pthread_t thread_pool[MAX_WORKERS];
    for (int i = 0; i < MAX_WORKERS; ++i) {
        pthread_create(&thread_pool[i], nullptr, worker_thread, nullptr);
    }

    // Main thread: accept incoming connections and push them into client_queue
    while (true) {
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        pthread_mutex_lock(&queue_mutex);
        client_queue.push(client_socket);
        pthread_cond_signal(&condition_var);
        pthread_mutex_unlock(&queue_mutex);
    }

    close(server_fd);
    return 0;
}
