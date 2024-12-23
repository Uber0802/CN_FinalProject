#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <cctype>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <portaudio.h>
#include <mpg123.h>
#include <opencv2/opencv.hpp>
#include <dispatch/dispatch.h> 
#include <opencv2/opencv.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgcodecs/imgcodecs.hpp>
#include <opencv2/imgproc/imgproc.hpp>

#include <fstream>
#include <filesystem>
#include <sys/stat.h>

#define PORT 8080

using namespace std;

bool logged_in = false;
bool interacting_with_server = false;

mutex mtx;
condition_variable cond_var;

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
    cond_var.notify_one();
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


#define CHUNK_SIZE 8192
#define FILE_TRANSFER_PORT_OFFSET 1 

struct FileTransferInfo {
    string filename;
    uintmax_t filesize;
};

void stream_file(SSL* ssl, const string& filepath) {
    string ext = filesystem::path(filepath).extension();
    bool is_video = (ext == ".mp4" || ext == ".avi");
    
    try {
        string header = (is_video ? "VIDEO:" : "AUDIO:") + filesystem::path(filepath).filename().string();
        if (SSL_write(ssl, header.c_str(), header.size()) <= 0) {
            throw runtime_error("Failed to send header");
        }

        if (is_video) {
            ifstream video_file(filepath, ios::binary);
            if (!video_file.is_open()) {
                throw runtime_error("Error opening video file");
            }

            unsigned char buffer[4096];
            while (video_file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || video_file.gcount() > 0) {
                size_t read_bytes = video_file.gcount();
                if (SSL_write(ssl, buffer, read_bytes) <= 0) {
                    throw runtime_error("Failed to send video data");
                }
            }

            video_file.close();

            uint32_t end_marker = 0;
            if (SSL_write(ssl, &end_marker, sizeof(end_marker)) <= 0) {
                throw runtime_error("Failed to send end marker");
            }
        } else {
            mpg123_handle *mh = nullptr;
            try {
                mpg123_init();
                mh = mpg123_new(NULL, NULL);
                
                if (mpg123_open(mh, filepath.c_str()) != MPG123_OK) {
                    throw runtime_error("Error opening audio file");
                }

                long rate;
                int channels, encoding;
                mpg123_getformat(mh, &rate, &channels, &encoding);

                if (SSL_write(ssl, &rate, sizeof(rate)) <= 0 ||
                    SSL_write(ssl, &channels, sizeof(channels)) <= 0) {
                    throw runtime_error("Failed to send audio format");
                }

                unsigned char buffer[4096];
                size_t done;
                while (mpg123_read(mh, buffer, sizeof(buffer), &done) == MPG123_OK) {
                    uint32_t chunk_size = done;
                    if (SSL_write(ssl, &chunk_size, sizeof(chunk_size)) <= 0 ||
                        SSL_write(ssl, buffer, done) <= 0) {
                        throw runtime_error("Failed to send audio data");
                    }
                    this_thread::sleep_for(chrono::milliseconds(10));
                }

                uint32_t end_marker = 0;
                if (SSL_write(ssl, &end_marker, sizeof(end_marker)) <= 0) {
                    throw runtime_error("Failed to send end marker");
                }

                mpg123_close(mh);
                mpg123_delete(mh);
                mh = nullptr;
            }
            catch (...) {
                if (mh) {
                    mpg123_close(mh);
                    mpg123_delete(mh);
                }
                throw;
            }
        }
        
        // Wait for completion confirmation from receiver
        char completion_msg[256] = {0};
        if (SSL_read(ssl, completion_msg, sizeof(completion_msg)) <= 0) {
            throw runtime_error("Failed to receive completion confirmation");
        }
        
        cout << "Stream completed successfully. Receiver message: " << completion_msg << endl;
    }
    catch (const exception& e) {
        cerr << "Streaming error: " << e.what() << endl;
    }
}


void receive_stream(SSL* ssl, const string& header, bool is_video) {
    try {
        if (is_video) {
            FILE* ffplay_pipe = popen("ffplay -i - -autoexit -hide_banner -loglevel quiet -x 1280 -y 720 > /dev/null 2>&1", "w");

            if (!ffplay_pipe) {
                throw runtime_error("Failed to open ffplay pipe");
            }

            try {
                while (true) {
                    unsigned char buffer[4096];
                    int read_bytes = SSL_read(ssl, buffer, sizeof(buffer));
                    if (read_bytes <= 0) {
                        throw runtime_error("Failed to receive video data");
                    }

                    if (read_bytes == sizeof(uint32_t)) {
                        uint32_t* marker = reinterpret_cast<uint32_t*>(buffer);
                        if (*marker == 0) {
                            break; 
                        }
                    }

                    if (fwrite(buffer, 1, read_bytes, ffplay_pipe) != static_cast<size_t>(read_bytes)) {
                        throw runtime_error("Failed to write video data to ffplay");
                    }

                    fflush(ffplay_pipe);
                }
            } catch (...) {
                pclose(ffplay_pipe);
                throw;
            }

            pclose(ffplay_pipe);
        } else if (header.find("VIDEO_STREAM:realtime") == 0) {
            FILE* ffplay_pipe = popen("ffplay -i - -autoexit -hide_banner -loglevel quiet -x 640 -y 480 > /dev/null 2>&1", "w");
            if (!ffplay_pipe) {
                throw runtime_error("Failed to open ffplay pipe");
            }

            try {
                while (true) {
                    uint32_t frame_size;
                    if (SSL_read(ssl, &frame_size, sizeof(frame_size)) <= 0) {
                        throw runtime_error("Failed to receive frame size");
                    }

                    if (frame_size == 0) break;

                    vector<unsigned char> buffer(frame_size);
                    if (SSL_read(ssl, buffer.data(), frame_size) <= 0) {
                        throw runtime_error("Failed to receive frame data");
                    }

                    if (fwrite(buffer.data(), 1, frame_size, ffplay_pipe) != frame_size) {
                        throw runtime_error("Failed to write to ffplay pipe");
                    }
                    fflush(ffplay_pipe);
                }
            } catch (...) {
                pclose(ffplay_pipe);
                throw;
            }
            pclose(ffplay_pipe);
        }
        else if (header.find("AUDIO_STREAM:realtime") == 0) {
            PaStream *stream = nullptr;
            atomic<bool> streaming{true};
            
            try {
                PaError err = Pa_Initialize();
                if (err != paNoError) {
                    throw runtime_error(string("PortAudio init error: ") + Pa_GetErrorText(err));
                }

                long rate;
                int channels;
                if (SSL_read(ssl, &rate, sizeof(rate)) <= 0 ||
                    SSL_read(ssl, &channels, sizeof(channels)) <= 0) {
                    throw runtime_error("Failed to receive audio format");
                }

                // Create an audio buffer to store incoming data
                const size_t BUFFER_SIZE = 8192;
                vector<float> audio_buffer;
                audio_buffer.reserve(BUFFER_SIZE);
                mutex buffer_mutex;
                condition_variable buffer_cv;

                // Output callback function
                auto outputCallback = [](const void *inputBuffer, void *outputBuffer,
                                    unsigned long framesPerBuffer,
                                    const PaStreamCallbackTimeInfo* timeInfo,
                                    PaStreamCallbackFlags statusFlags,
                                    void *userData) -> int {
                    auto data = static_cast<pair<vector<float>*, mutex*>*>(userData);
                    auto& buffer = *(data->first);
                    auto& mtx = *(data->second);
                    float *out = static_cast<float*>(outputBuffer);

                    lock_guard<mutex> lock(mtx);
                    if (buffer.empty()) {
                        // If no data, output silence
                        memset(out, 0, framesPerBuffer * sizeof(float));
                        return paContinue;
                    }

                    // Copy available data to output buffer
                    size_t frames_to_copy = min(framesPerBuffer, buffer.size());
                    memcpy(out, buffer.data(), frames_to_copy * sizeof(float));

                    // Clear used data from buffer
                    buffer.erase(buffer.begin(), buffer.begin() + frames_to_copy);

                    return paContinue;
                };

                // Open output stream with callback
                err = Pa_OpenDefaultStream(&stream,
                                        0,              // no input channels
                                        channels,       // mono/stereo output
                                        paFloat32,      // sample format
                                        rate,           // sample rate
                                        256,            // frames per buffer
                                        outputCallback, // callback function
                                        new pair<vector<float>*, mutex*>(&audio_buffer, &buffer_mutex));

                if (err != paNoError) {
                    throw runtime_error(string("PortAudio stream error: ") + Pa_GetErrorText(err));
                }

                err = Pa_StartStream(stream);
                if (err != paNoError) {
                    throw runtime_error(string("Failed to start stream: ") + Pa_GetErrorText(err));
                }

                cout << "Receiving audio stream. Press Enter to stop..." << endl;

                // Start a thread to handle user input
                thread input_thread([&streaming]() {
                    cin.get();
                    streaming = false;
                });
                input_thread.detach();

                // Main reception loop
                while (streaming) {
                    uint32_t chunk_size;
                    int read_result = SSL_read(ssl, &chunk_size, sizeof(chunk_size));
                    
                    if (read_result <= 0) {
                        int ssl_error = SSL_get_error(ssl, read_result);
                        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                            this_thread::sleep_for(chrono::milliseconds(1));
                            continue;
                        }
                        break;
                    }

                    if (chunk_size == 0) break;

                    vector<int16_t> samples(chunk_size / sizeof(int16_t));
                    if (SSL_read(ssl, samples.data(), chunk_size) <= 0) {
                        break;
                    }

                    // Convert and add to buffer
                    {
                        lock_guard<mutex> lock(buffer_mutex);
                        for (int16_t sample : samples) {
                            audio_buffer.push_back(sample / 32768.0f);
                        }
                    }
                    buffer_cv.notify_one();
                }

                // Clean up
                Pa_StopStream(stream);
                Pa_CloseStream(stream);
                Pa_Terminate();

                cout << "Audio stream ended" << endl;

                // Send completion acknowledgment
                string completion_msg = "Audio stream received successfully";
                SSL_write(ssl, completion_msg.c_str(), completion_msg.length());
            }
            catch (const exception& e) {
                if (stream) {
                    Pa_StopStream(stream);
                    Pa_CloseStream(stream);
                    Pa_Terminate();
                }
                cerr << "Error in audio streaming: " << e.what() << endl;
                throw;
            }
        } else {
            PaStream *stream = nullptr;
            try {
                PaError err = Pa_Initialize();
                if (err != paNoError) {
                    throw runtime_error(string("PortAudio init error: ") + Pa_GetErrorText(err));
                }

                long rate;
                int channels;
                if (SSL_read(ssl, &rate, sizeof(rate)) <= 0 ||
                    SSL_read(ssl, &channels, sizeof(channels)) <= 0) {
                    throw runtime_error("Failed to receive audio format");
                }

                err = Pa_OpenDefaultStream(&stream,
                                         0,
                                         channels,
                                         paFloat32,
                                         rate,
                                         paFramesPerBufferUnspecified,
                                         NULL,
                                         NULL);

                if (err != paNoError) {
                    throw runtime_error(string("PortAudio stream error: ") + Pa_GetErrorText(err));
                }

                Pa_StartStream(stream);

                while (true) {
                    uint32_t chunk_size;
                    if (SSL_read(ssl, &chunk_size, sizeof(chunk_size)) <= 0) {
                        throw runtime_error("Failed to receive chunk size");
                    }
                    
                    if (chunk_size == 0) break;
                    
                    vector<unsigned char> buffer(chunk_size);
                    if (SSL_read(ssl, buffer.data(), chunk_size) <= 0) {
                        throw runtime_error("Failed to receive audio data");
                    }
                    
                    vector<float> float_buffer(chunk_size / 2);
                    for (size_t i = 0; i < chunk_size; i += 2) {
                        int16_t sample = buffer[i] | (buffer[i + 1] << 8);
                        float_buffer[i/2] = sample / 32768.0f;
                    }
                    
                    Pa_WriteStream(stream, float_buffer.data(), float_buffer.size() / channels);
                }

                Pa_StopStream(stream);
                Pa_CloseStream(stream);
                Pa_Terminate();
            }
            catch (...) {
                if (stream) {
                    Pa_StopStream(stream);
                    Pa_CloseStream(stream);
                    Pa_Terminate();
                }
                throw;
            }
        }

        string completion_msg = "Stream received successfully!";
        if (SSL_write(ssl, completion_msg.c_str(), completion_msg.size()) <= 0) {
            throw runtime_error("Failed to send completion confirmation");
        }
        
        cout << "Video/audio displayed successfully" << endl;
    }
    catch (const exception& e) {
        cerr << "Receiving error: " << e.what() << endl;

        string error_msg = "Error during reception: " + string(e.what());
        SSL_write(ssl, error_msg.c_str(), error_msg.size());
    }
}


// Add these new functions after the existing ones and before main()

void send_file(SSL* ssl, const string& filepath) {
    ifstream file(filepath, ios::binary);
    if (!file) {
        cerr << "Cannot open file: " << filepath << endl;
        return;
    }

    // Get file size
    struct stat file_stat;
    stat(filepath.c_str(), &file_stat);
    size_t file_size = file_stat.st_size;

    // Get filename from path
    string filename = filesystem::path(filepath).filename().string();
    
    // Send filename and size first
    string header = "FILE_HEADER:" + filename + ":" + to_string(file_size);
    SSL_write(ssl, header.c_str(), header.size());

    // Send file in chunks
    const size_t chunk_size = 8192;
    char buffer[chunk_size];
    size_t total_sent = 0;

    while (total_sent < file_size) {
        file.read(buffer, chunk_size);
        size_t bytes_read = file.gcount();
        SSL_write(ssl, buffer, bytes_read);
        total_sent += bytes_read;

        // Show progress
        float progress = (float)total_sent / file_size * 100;
        cout << "\rSending file... " << progress << "%" << flush;
    }
    cout << "\nFile sent successfully!" << endl;
    file.close();
}

void receive_file(SSL* ssl, const string& header) {
    // Parse header
    string filename = header.substr(header.find(":") + 1);
    size_t size_pos = filename.find(":");
    size_t file_size = stoull(filename.substr(size_pos + 1));
    filename = filename.substr(0, size_pos);

    cout << "\nReceiving file: " << filename << " (Size: " << file_size << " bytes)" << endl;

    // Create 'downloads' directory if it doesn't exist
    filesystem::create_directory("downloads");
    
    // Open file for writing
    string save_path = "downloads/" + filename;
    ofstream file(save_path, ios::binary);
    if (!file) {
        cerr << "Cannot create file: " << save_path << endl;
        return;
    }

    // Receive file in chunks
    const size_t chunk_size = 8192;
    char buffer[chunk_size];
    size_t total_received = 0;

    while (total_received < file_size) {
        size_t to_read = min(chunk_size, file_size - total_received);
        int bytes_read = SSL_read(ssl, buffer, to_read);
        if (bytes_read <= 0) break;
        
        file.write(buffer, bytes_read);
        total_received += bytes_read;

        // Show progress
        float progress = (float)total_received / file_size * 100;
        cout << "\rReceiving file... " << progress << "%" << flush;
    }
    cout << "\nFile saved as: " << save_path << endl;
    file.close();
}




struct AudioStreamData {
    vector<float> buffer;
    mutex mtx;
    condition_variable cv;
    bool finished = false;
};

// Callback function for PortAudio input stream
static int recordCallback(const void *inputBuffer, void *outputBuffer,
                         unsigned long framesPerBuffer,
                         const PaStreamCallbackTimeInfo* timeInfo,
                         PaStreamCallbackFlags statusFlags,
                         void *userData) {
    AudioStreamData *data = (AudioStreamData*)userData;
    const float *in = (const float*)inputBuffer;
    
    lock_guard<mutex> lock(data->mtx);
    // Copy input data to our buffer
    for (unsigned long i = 0; i < framesPerBuffer; i++) {
        data->buffer.push_back(in[i]);
    }
    data->cv.notify_one();
    
    return paContinue;
}

void stream_realtime_audio(SSL* ssl) {
    PaStream *stream;
    AudioStreamData streamData;
    PaError err;

    err = Pa_Initialize();
    if (err != paNoError) {
        cerr << "PortAudio error: " << Pa_GetErrorText(err) << endl;
        return;
    }

    // Open an audio input stream
    err = Pa_OpenDefaultStream(&stream,
                             1,          // mono input
                             0,          // no output
                             paFloat32,  // sample format
                             44100,      // sample rate
                             256,        // frames per buffer
                             recordCallback,
                             &streamData);
    
    if (err != paNoError) {
        cerr << "Error opening stream: " << Pa_GetErrorText(err) << endl;
        Pa_Terminate();
        return;
    }

    // Send header and audio format info
    string header = "AUDIO_STREAM:realtime";
    SSL_write(ssl, header.c_str(), header.length());
    
    long rate = 44100;
    int channels = 1;
    SSL_write(ssl, &rate, sizeof(rate));
    SSL_write(ssl, &channels, sizeof(channels));

    err = Pa_StartStream(stream);
    if (err != paNoError) {
        cerr << "Error starting stream: " << Pa_GetErrorText(err) << endl;
        Pa_CloseStream(stream);
        Pa_Terminate();
        return;
    }

    cout << "Recording... Press Enter to stop." << endl;

    // Start a thread to read input
    thread input_thread([&streamData]() {
        cin.get();
        lock_guard<mutex> lock(streamData.mtx);
        streamData.finished = true;
        streamData.cv.notify_one();
    });
    input_thread.detach();

    // Main streaming loop
    while (true) {
        unique_lock<mutex> lock(streamData.mtx);
        streamData.cv.wait(lock, [&]() { 
            return !streamData.buffer.empty() || streamData.finished; 
        });

        if (!streamData.buffer.empty()) {
            // Convert float samples to int16
            vector<int16_t> samples;
            for (float f : streamData.buffer) {
                samples.push_back(f * 32767);
            }
            
            // Send chunk size and data
            uint32_t chunk_size = samples.size() * sizeof(int16_t);
            SSL_write(ssl, &chunk_size, sizeof(chunk_size));
            SSL_write(ssl, samples.data(), chunk_size);
            
            streamData.buffer.clear();
        }

        if (streamData.finished && streamData.buffer.empty()) {
            break;
        }
    }

    // Send end marker
    uint32_t end_marker = 0;
    SSL_write(ssl, &end_marker, sizeof(end_marker));

    Pa_StopStream(stream);
    Pa_CloseStream(stream);
    Pa_Terminate();

    // Wait for completion confirmation
    char completion_msg[256] = {0};
    SSL_read(ssl, completion_msg, sizeof(completion_msg));
    cout << "Stream audio completed"<< endl;
}

void stream_realtime_video(SSL* ssl) {
    cv::VideoCapture cap(0); // Open default camera
    if (!cap.isOpened()) {
        cerr << "Error: Could not open camera" << endl;
        return;
    }

    // Set resolution
    cap.set(cv::CAP_PROP_FRAME_WIDTH, 640);
    cap.set(cv::CAP_PROP_FRAME_HEIGHT, 480);

    // Send header
    string header = "VIDEO_STREAM:realtime";
    SSL_write(ssl, header.c_str(), header.length());

    cout << "Recording video... Press Enter to stop." << endl;

    // Create atomic flag for thread synchronization
    atomic<bool> recording{true};

    // Thread to handle user input
    thread input_thread([&recording]() {
        cin.get();
        recording = false;
    });
    input_thread.detach();

    cv::Mat frame;
    vector<uchar> buffer;

    // Main recording loop
    while (recording) {
        cap >> frame;
        if (frame.empty()) break;

        // Encode frame to jpg
        cv::imencode(".jpg", frame, buffer);

        // Send frame size and data
        uint32_t frame_size = buffer.size();
        SSL_write(ssl, &frame_size, sizeof(frame_size));
        SSL_write(ssl, buffer.data(), frame_size);
    }

    // Send end marker
    uint32_t end_marker = 0;
    SSL_write(ssl, &end_marker, sizeof(end_marker));
    cap.release();

    // Wait for completion confirmation
    char completion_msg[256] = {0};
    SSL_read(ssl, completion_msg, sizeof(completion_msg));
    cout << "Stream webcam completed" << endl;
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
                // cout << "\n[Direct Message Received]: " << buffer << endl;
                string message(buffer);
                // cout << "message: " << message << endl;
                if (message.rfind("FILE_HEADER:", 0) == 0) {
                    receive_file(direct_ssl, message);
                }
                else if (message.rfind("VIDEO:", 0) == 0) {
                    std::string delimiter = ":";
                    size_t pos = message.find(delimiter);
                    std::string filename;
                    if (pos != std::string::npos) {
                        filename = message.substr(pos + delimiter.length());
                    }
                    cout << "Received a video: " << filename << endl;
                    receive_stream(direct_ssl, message, 1);
                }
                else if (message.rfind("AUDIO:", 0) == 0) {
                    std::string delimiter = ":";
                    size_t pos = message.find(delimiter);
                    std::string filename;
                    if (pos != std::string::npos) {
                        filename = message.substr(pos + delimiter.length());
                    }
                    cout << "Received an audio: " << filename << endl;
                    receive_stream(direct_ssl, message, 0);
                }
                else if (message.rfind("AUDIO_STREAM:realtime", 0) == 0) {
                    cout << "Received an AUDIO_STREAM:realtime" << endl;
                    receive_stream(direct_ssl, message, 0);
                }
                else if (message.rfind("VIDEO_STREAM:realtime", 0) == 0) {
                    cout << "Received an VIDEO_STREAM:realtime" << endl;
                    receive_stream(direct_ssl, message, 1);
                }
                else {
                    cout << "\n[Direct Message Received]: " << buffer << endl;
                }
            } else if (bytes == 0) {
                break;
            } else {
                int err = SSL_get_error(direct_ssl, bytes);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    break;
                } else {
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

        if (message.rfind("MSG:", 0) == 0) {
            if (!interacting_with_server) {
                cout << "\n[Message Received]: " << message.substr(4) << endl;
            }
        } else if (message.rfind("SERVER:", 0) == 0) {
            string server_message = message.substr(7);
            cout << "==================================================" << endl;
            cout << "Server: " << server_message << endl;
            // cout << "==================================================" << endl;

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
            else if (server_message.find("Online users (file transfer):") != string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send a file to: ";
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

                        cout << "Enter the path to the file you want to send: ";
                        string filepath;
                        getline(cin, filepath);
                        rtrim(filepath);

                        if (!filesystem::exists(filepath)) {
                            cout << "File does not exist!" << endl;
                            signal_interaction_finished();
                            continue;
                        }

                        int direct_sock = socket(AF_INET, SOCK_STREAM, 0);
                        struct sockaddr_in target_addr;
                        memset(&target_addr, 0, sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_port = htons(target_port);
                        inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr);

                        if (connect(direct_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                            cout << "Failed to connect to target user." << endl;
                            close(direct_sock);
                            signal_interaction_finished();
                            continue;
                        }

                        SSL *direct_ssl = SSL_new(client_ctx);
                        SSL_set_fd(direct_ssl, direct_sock);
                        if (SSL_connect(direct_ssl) <= 0) {
                            ERR_print_errors_fp(stderr);
                            close(direct_sock);
                            SSL_free(direct_ssl);
                            signal_interaction_finished();
                            continue;
                        }

                        send_file(direct_ssl, filepath);
                        
                        SSL_shutdown(direct_ssl);
                        SSL_free(direct_ssl);
                        close(direct_sock);
                        signal_interaction_finished();
                    }
                }
            }
            else if (server_message.find("Online users (audio transfer):") != string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to send audio to: ";
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

                        cout << "Enter the path to the file you want to send: ";
                        string filepath;
                        getline(cin, filepath);
                        rtrim(filepath);

                        if (!filesystem::exists(filepath)) {
                            cout << "File does not exist!" << endl;
                            signal_interaction_finished();
                            continue;
                        }

                        int direct_sock = socket(AF_INET, SOCK_STREAM, 0);
                        struct sockaddr_in target_addr;
                        memset(&target_addr, 0, sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_port = htons(target_port);
                        inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr);

                        if (connect(direct_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                            cout << "Failed to connect to target user." << endl;
                            close(direct_sock);
                            signal_interaction_finished();
                            continue;
                        }

                        SSL *direct_ssl = SSL_new(client_ctx);
                        SSL_set_fd(direct_ssl, direct_sock);
                        if (SSL_connect(direct_ssl) <= 0) {
                            ERR_print_errors_fp(stderr);
                            close(direct_sock);
                            SSL_free(direct_ssl);
                            signal_interaction_finished();
                            continue;
                        }

                        stream_file(direct_ssl, filepath);
                        
                        SSL_shutdown(direct_ssl);
                        SSL_free(direct_ssl);
                        close(direct_sock);
                        signal_interaction_finished();
                    }
                }
            }

            else if (server_message.find("Online users (realtime audio with microphone):") != string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to audio talk to: ";
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

                        int direct_sock = socket(AF_INET, SOCK_STREAM, 0);
                        struct sockaddr_in target_addr;
                        memset(&target_addr, 0, sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_port = htons(target_port);
                        inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr);

                        if (connect(direct_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                            cout << "Failed to connect to target user." << endl;
                            close(direct_sock);
                            signal_interaction_finished();
                            continue;
                        }

                        SSL *direct_ssl = SSL_new(client_ctx);
                        SSL_set_fd(direct_ssl, direct_sock);
                        if (SSL_connect(direct_ssl) <= 0) {
                            ERR_print_errors_fp(stderr);
                            close(direct_sock);
                            SSL_free(direct_ssl);
                            signal_interaction_finished();
                            continue;
                        }

                        stream_realtime_audio(direct_ssl);
                        
                        SSL_shutdown(direct_ssl);
                        SSL_free(direct_ssl);
                        close(direct_sock);
                        signal_interaction_finished();
                    }
                }
            }
            else if (server_message.find("Online users (realtime video with webcam):") != string::npos) {
                {
                    lock_guard<mutex> lock(mtx);
                    interacting_with_server = true;
                }
                cout << "Choose a user to video call to: ";
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

                        int direct_sock = socket(AF_INET, SOCK_STREAM, 0);
                        struct sockaddr_in target_addr;
                        memset(&target_addr, 0, sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_port = htons(target_port);
                        inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr);

                        if (connect(direct_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                            cout << "Failed to connect to target user." << endl;
                            close(direct_sock);
                            signal_interaction_finished();
                            continue;
                        }

                        SSL *direct_ssl = SSL_new(client_ctx);
                        SSL_set_fd(direct_ssl, direct_sock);
                        if (SSL_connect(direct_ssl) <= 0) {
                            ERR_print_errors_fp(stderr);
                            close(direct_sock);
                            SSL_free(direct_ssl);
                            signal_interaction_finished();
                            continue;
                        }

                        stream_realtime_video(direct_ssl);
                        
                        SSL_shutdown(direct_ssl);
                        SSL_free(direct_ssl);
                        close(direct_sock);
                        signal_interaction_finished();
                    }
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

    cout << "#################################################" << endl;
    cout << "#           Real-time Online Chatroom           #" << endl;
    cout << "#################################################\n" << endl;

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
                cond_var.wait(lock);
            }
        }

        cout << "==================================================" << endl;
        
        if (!logged_in) {
            cout << "1. Register\n";
            cout << "2. Login\n";
            cout << "3. Exit\n";
        } else {
            cout << "1. Logout\n";
            cout << "2. Send Message (Relay mode)\n";
            cout << "3. Send Message (Direct mode)\n";
            cout << "4. Send File (Direct mode)\n";
            cout << "5. Send audio\n";
            cout << "6. Send video\n";
            cout << "7. Stream Microphone\n";  // New option
            cout << "8. Stream Webcam\n";      // New option
            cout << "9. Exit\n";
        }
        cout << "==================================================" << endl;
        cout << "Please Select a service: \n";

        string choice;
        getline(cin, choice);
        rtrim(choice);
        SSL_write(server_ssl, choice.c_str(), choice.size());

        if ((!logged_in && choice == "3") || (logged_in && choice == "9")) {
            cout << "Exiting...\n";
            break;
        }

        if (!logged_in) {
            if (choice == "1" || choice == "2") {
                lock_guard<mutex> lock(mtx);
                interacting_with_server = true;
            }
        } else {
            if (choice == "1" || choice == "2" || choice == "3" || choice == "4" || 
                choice == "5" || choice == "6" || choice == "7" || choice == "8") {
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