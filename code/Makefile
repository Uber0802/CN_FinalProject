CXX = g++
CXXFLAGS = -std=c++17 -I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/include/opencv4 \
 -I/opt/homebrew/include \
 -O2 -march=native

LDFLAGS = -pthread -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/lib -lssl -lcrypto \
 -lopencv_core -lopencv_imgcodecs -lopencv_highgui -lopencv_imgproc -lopencv_videoio \
 -lportaudio -lmpg123 \
 -framework Foundation -framework AppKit -framework CoreFoundation -framework CoreGraphics \
 -framework CoreVideo -framework QuartzCore -framework AVFoundation \
 -framework CoreMedia  # Add CoreMedia framework



# Targets
TARGETS = server client

# Source files
SERVER_SRC = server.cpp
CLIENT_SRC = client.cpp

# Executable files
SERVER_EXEC = server
CLIENT_EXEC = client

# Default certificates for server and client
SERVER_CRT = server.crt
SERVER_KEY = server.key
CA_CRT = ca.crt
CLIENT_CRT = client_server.crt
CLIENT_KEY = client_server.key

# Build all targets
all: $(TARGETS)

# Build server
server: $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $(SERVER_EXEC) $(SERVER_SRC) $(LDFLAGS)

# Build client
client: $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $(CLIENT_EXEC) $(CLIENT_SRC) $(LDFLAGS)

# Clean up build artifacts
clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC)

# Run server
run-server:
	./$(SERVER_EXEC) $(SERVER_CRT) $(SERVER_KEY)

# Run client
run-client:
	./$(CLIENT_EXEC) $(CA_CRT) $(CLIENT_CRT) $(CLIENT_KEY)