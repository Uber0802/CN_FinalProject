# Simple Client-Server Application

This repository contains a basic client-server application that allows users to register, log in, log out, and exit. 

## Files

- **server.cpp**: The server file that listens for client connections and processes registration, login, logout, and exit requests.
- **client.cpp**: The client file that connects to the server and provides an interface for users to interact with the server.

## Features

- **Register**: Allows a new user to register with a username and password.
- **Login**: Allows an existing user to log in using their username and password.
- **Logout**: Logs out the currently logged-in user.
- **Exit**: Closes the client connection to the server.

## Service

It will provide what service can the client use after every operation. When client is not log in it can use register, login and exit service, if client is log in it can use register, logout and exit service.
By entering the number specify for that service, it can start using the specific service.
- **Register** : enter <username> <password> (ex. apple 1234)
- **Login**: enter <username> <password> (ex. apple 1234) If success, it will reply Login successful. If not success, it will reply Login failed: incorrect username or password.
- **Logout**: Log out directly and reply Logged out successfully.
- **Exit**: Exit directly 

If there is unspecify request it will reply Incorrect service request.

## Prerequisites

- A C++ compiler that supports C++11 or later.
- POSIX-compliant operating system (Linux, macOS, etc.).

## Compilation

To compile both server and client files, use the following commands:

```bash
g++ -std=c++11 server.cpp -o server -pthread
g++ -std=c++11 client.cpp -o client
```

## Execution

```
./server
./client
```