// MIT License

// Copyright (c) 2024 W.M.R Jap-A-Joe

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Special thanks to https://github.com/tsoding/cws for reference

#include "wspp.h"
#include <random>
#include <regex>
#include <utility>

#include <iostream>
#include <iomanip>

namespace wspp {
    void dumpFrame(OpCode opcode, const uint8_t *data, size_t size) {
        // Check if the data pointer is null
        if (data == nullptr) {
            std::cout << "No data to display." << std::endl;
            return;
        }

        std::cout << "OpCode: " << static_cast<int>(opcode) << '\n';

        // Iterate through each byte in the data
        for (size_t i = 0; i < size; ++i) {
            // Print each byte in hexadecimal format
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";
            
            // Optionally, print a newline every 16 bytes for better readability
            if ((i + 1) % 16 == 0) {
                std::cout << std::endl;
            }
        }
        std::cout << std::dec << std::endl; // Reset to decimal format
    }

    ///////////////
    ///[Message]///
    ///////////////

    Message::Message() {
        opcode = OpCode::Continuation;
        chunks = nullptr;
    }

    Message::Message(const Message &other) noexcept {
        opcode = other.opcode;
        chunks = other.chunks;
    }

    Message::Message(Message &&other) {
        opcode = other.opcode;
        chunks = std::exchange(other.chunks, nullptr);
    }

    Message& Message::operator=(const Message &other) {
        if(this != &other) {
            opcode = other.opcode;
            chunks = other.chunks;
        }
        return *this;
    }

    Message& Message::operator=(Message &&other) noexcept {
        if(this != &other) {
            opcode = other.opcode;
            chunks = std::exchange(other.chunks, nullptr);
        }
        return *this;
    }

    void Message::destroy() {
        MessageChunk *current = chunks;
        
        while (current != nullptr) {
            if(current->payload)
                delete[] current->payload;
            MessageChunk *previous = current;
            current = current->next;
            delete previous;
        }

        chunks = nullptr;
    }

    bool Message::getText(std::string &s) {
        MessageChunk *chunk = chunks;
        bool success = false;

        while(chunk) {
            char *payload = (char*)chunk->payload;
            if(payload == nullptr) {
                printf("Message::getText: payload = nullptr\n");
                return false;
            }

            if(chunk->payloadLength == 0) {
                printf("Message::getText: payloadLength = 0\n");
                return false;
            }

            s += std::string(payload, chunk->payloadLength);
            chunk = chunk->next;
            success = true;
        }

        return success;
    }

    bool Message::getRaw(std::vector<uint8_t> &data) {
        MessageChunk *chunk = chunks;
        size_t totalSize = 0;

        while(chunk) {
            totalSize += chunk->payloadLength;
            chunk = chunk->next;
        }

        size_t index = 0;

        if(totalSize > 0) {
            data.resize(totalSize);

            chunk = chunks;

            while(chunk) {
                memcpy(&data[index], chunk->payload, chunk->payloadLength);
                index += chunk->payloadLength;
                chunk = chunk->next;
            }
        }

        return data.size() > 0;
    }

    ///////////////
    //[WebSocket]//
    ///////////////

#ifdef _WIN32
    static bool winsockInitialized = false;
#endif

    void initialize() {
    #ifdef _WIN32
        if(winsockInitialized)
            return;
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
            printf("Failed to initialize winsock\n")
            winsockInitialized = true;
        }
    #endif        
    }

    void deinitialize() {
    #ifdef _WIN32
        if(!winsockInitialized)
            return;
        WSACleanup();
        winsockInitialized = false;
    #endif
    }

    //Function to check if this system is little or big endian
    static bool isLittleEndian() {
        uint16_t num = 1;
        uint8_t* ptr = reinterpret_cast<uint8_t*>(&num);
        return ptr[0] == 1; // If the least significant byte is 1, it's little-endian
    }

    static void swapBytes(void *buffer, size_t size) {
        if(size < 2)
            return;
        
        uint8_t *bytes = reinterpret_cast<uint8_t*>(buffer);

        for (size_t i = 0; i < size / 2; ++i) {
            uint8_t temp = bytes[i];
            bytes[i] = bytes[size - i - 1];
            bytes[size - i - 1] = temp;
        }
    }

    //The following 2 methods do the same thing but it helps readability
    static void networkToHostOrder(void *src, void *dest, size_t size) {
        if(isLittleEndian()) {
            swapBytes(src, size);
        }
        memcpy(dest, src, size);
    }

    static void hostToNetworkOrder(void *src, void *dest, size_t size) {
        if(isLittleEndian()) {
            swapBytes(src, size);
        }
        memcpy(dest, src, size);
    }

    WebSocket::WebSocket() {
        memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
        s.addressFamily = AddressFamily::AFInet;
        sslContext = nullptr;
        ssl = nullptr;
        onError = nullptr;
        onReceived = nullptr;
    }

    WebSocket::WebSocket(AddressFamily addressFamily) {
        memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
        s.addressFamily = addressFamily;
        sslContext = nullptr;
        ssl = nullptr;
        onError = nullptr;
        onReceived = nullptr;
    }

    WebSocket::WebSocket(AddressFamily addressFamily, const std::string &certificatePath, const std::string &privateKeyPath) {
        memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
        s.addressFamily = addressFamily;
        sslContext = nullptr;
        ssl = nullptr;
        onError = nullptr;
        onReceived = nullptr;

        sslContext = SSL_CTX_new(TLS_server_method());

        if(sslContext != nullptr) {
            if (SSL_CTX_use_certificate_file(sslContext, certificatePath.c_str(), SSL_FILETYPE_PEM) <= 0) {
                SSL_CTX_free(sslContext);
                sslContext = nullptr;
                return;
            }

            if (SSL_CTX_use_PrivateKey_file(sslContext, privateKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
                SSL_CTX_free(sslContext);
                sslContext = nullptr;
                return;
            }

            if (!SSL_CTX_check_private_key(sslContext)) {
                SSL_CTX_free(sslContext);
                sslContext = nullptr;
            }
        }
    }

    WebSocket::WebSocket(const WebSocket &other) {
        s = other.s;
        s.addressFamily = other.s.addressFamily;
        sslContext = other.sslContext;
        ssl = other.ssl;
        onError = other.onError;
        onReceived = other.onReceived;
    }

    WebSocket::WebSocket(WebSocket &&other) noexcept {
        memcpy(&s, &other.s, sizeof(other.s));
        other.s.fd = -1;
        sslContext = std::exchange(other.sslContext, nullptr);
        ssl = std::exchange(other.ssl, nullptr);
        onError = std::exchange(other.onError, nullptr);
        onReceived = std::exchange(other.onReceived, nullptr);
    }

    WebSocket::~WebSocket() {
        close();
    }

    WebSocket& WebSocket::operator=(const WebSocket &other) {
        if(this != &other) {
            s = other.s;
            sslContext = other.sslContext;
            ssl = other.ssl;
            onError = other.onError;
            onReceived = other.onReceived;
        }
        return *this;
    }

    WebSocket& WebSocket::operator=(WebSocket &&other) noexcept {
        if(this != &other) {
            memcpy(&s, &other.s, sizeof(other.s));
            other.s.fd = -1;
            sslContext = std::exchange(other.sslContext, nullptr);
            ssl = std::exchange(other.ssl, nullptr);
            onError = std::exchange(other.onError, nullptr);
            onReceived = std::exchange(other.onReceived, nullptr);
        }
        return *this;
    }

    bool WebSocket::bind(const std::string &bindAddress, uint16_t port) {
        if(s.fd < 0) {
            int32_t newfd = ::socket(static_cast<int>(s.addressFamily), SOCK_STREAM, 0);
            if(newfd < 0) {
                writeError("WebSocket::bind: failed to create socket");
                return false;
            }
            s.fd = newfd;
        }

        if (s.addressFamily == AddressFamily::AFInet) {
            sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            address.sin_addr.s_addr = INADDR_ANY;

            // If you want to bind to a specific address, use inet_pton
            if (inet_pton(AF_INET, bindAddress.c_str(), &address.sin_addr) <= 0) {
                writeError("WebSocket::bind: failed set bind address");
                return false;
            }

            memcpy(&s.address.ipv4, &address, sizeof(sockaddr_in));

            int reuseFlag = 1;
            setOption(SOL_SOCKET, SO_REUSEADDR, &reuseFlag, sizeof(int));

            int noDelayFlag = 1;
            setOption(IPPROTO_TCP, TCP_NODELAY, (char *)&noDelayFlag, sizeof(int));

            return ::bind(s.fd, (struct sockaddr*)&address, sizeof(address)) == 0;
        } else if (s.addressFamily == AddressFamily::AFInet6) {
            sockaddr_in6 address = {0};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(port);
            address.sin6_addr = in6addr_any;

            // If you want to bind to a specific address, use inet_pton
            if (inet_pton(AF_INET6, bindAddress.c_str(), &address.sin6_addr) <= 0) {
                writeError("WebSocket::bind: failed set bind address");
                return false;
            }

            memcpy(&s.address.ipv4, &address, sizeof(sockaddr_in6));

            int reuse = 1;
            setOption(SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            return ::bind(s.fd, (struct sockaddr*)&address, sizeof(address)) == 0;
        }

        writeError("WebSocket::bind: invalid address family");

        return false;
    }

    bool WebSocket::listen(int32_t backlog) {
        if(s.fd < 0) {
            writeError("WebSocket::listen: failed to listen because socket isn't initialized");
            return false;
        }
        return ::listen(s.fd, backlog) == 0;
    }

    bool WebSocket::accept(WebSocket &client) {
        if(s.fd < 0) {
            writeError("WebSocket::accept: failed to accept because socket isn't initialized");
            return false;
        }

        if(client.s.fd >= 0) {
            writeError("WebSocket::accept: failed to accept client because its socket is already initialized");
            return false;
        }

        struct sockaddr addr;
        memset(&addr, 0, sizeof(addr));
        uint32_t size = 0;
        
    #ifdef _WIN32
        client.s.fd = ::accept(s.fd,  &addr, (int32_t*)&size);
    #else
        client.s.fd = ::accept(s.fd,  &addr, &size);
    #endif
        
        if(client.s.fd < 0) {
            return false;
        }
        
        if(size == sizeof(sockaddr_in_t)) {
            memcpy(&client.s.address.ipv4, &addr, size);
            client.s.addressFamily = AddressFamily::AFInet;
        } else if(size == sizeof(sockaddr_in6_t)) {
            memcpy(&client.s.address.ipv6, &addr, size);
            client.s.addressFamily = AddressFamily::AFInet6;
        } else {
            printf("Unknown address family\n");
            writeError("WebSocket::accept: failed to set client address family");
            client.close();
            return false;
        }

        if(sslContext) {
            client.ssl = SSL_new(sslContext);
            
            if(client.ssl == nullptr) {
                writeError("WebSocket::accept: failed to create client SSL");
                client.close();
                return false;
            }

            SSL_set_fd(client.ssl, client.s.fd);

            if (SSL_accept(client.ssl) <= 0) {
                writeError("WebSocket::accept: failed to set client SSL file descriptor");
                SSL_shutdown(client.ssl);
                SSL_free(client.ssl);
                client.ssl = nullptr;
                client.close();
                return false;
            }
        }

        std::string header;
        std::string path;
        HttpMethod method;

        if(!readHeader(client, header)) {
            writeError("WebSocket::accept: failed to read header");
            sendBadRequest(client);
            return false;
        }

        if(!readMethod(header, method)) {
            writeError("WebSocket::accept: failed read HTTP method from header");
            sendBadRequest(client);
            return false;
        }
        
        if(!readPath(header, path)) {
            writeError("WebSocket::accept: failed to read path from header");
            sendBadRequest(client);
            return false;
        }

        Headers headers;
        
        if(!readHeaderFields(header, headers)) {
            writeError("WebSocket::accept: failed to read header fields");
            sendBadRequest(client);
            return false;
        }

        if(method != HttpMethod::GET) {
            writeError("WebSocket::accept: invalid HTTP method");
            sendBadRequest(client);
            return false;
        }

        const std::vector<std::string> requiredHeaders = {
            "Upgrade", "Connection", "Sec-WebSocket-Version", "Sec-WebSocket-Key"
        };

        for (const auto &key : requiredHeaders) {
            if (headers.count(key) == 0) {
                writeError("WebSocket::accept: missing required header field: " + key);
                sendBadRequest(client);
                return false;
            }
        }

        std::string upgrade = headers["Upgrade"];
        std::string connection = headers["Connection"];
        std::string version = headers["Sec-WebSocket-Version"];
        std::string webKey = headers["Sec-WebSocket-Key"];

        if(upgrade != "websocket") {
            writeError("WebSocket::accept: failed to find 'websocket'");
            sendBadRequest(client);
            return false;
        }

        if(!String::contains(connection, "Upgrade")) {
            writeError("WebSocket::accept: failed to find 'Upgrade'");
            sendBadRequest(client);
            return false;
        }

        if(version != "13") {
            writeError("WebSocket::accept: version mismatch");
            sendBadRequest(client);
            return false;
        }

        std::string acceptKey = generateAcceptKey(webKey);

        std::string response = "HTTP/1.1 101 Switching Protocols\r\n";
        response += "Upgrade: websocket\r\n";
        response += "Connection: Upgrade\r\n";
        response += "Server: Testing\r\n";
        response += "Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n";

        ssize_t sentBytes = client.write(response.data(), response.size());

        if(sentBytes <= 0) {
            writeError("WebSocket::accept: failed to send handshake response");
            client.close();
            return false;
        }
        
        return true;
    }

    bool WebSocket::connect(const std::string &uri) {
        if(s.fd >= 0)
            return false;

        std::string URL = uri;

        if(!String::endsWith(URL, "/"))
            URL += "/";

        std::string scheme;

        if(!URI::getScheme(URL, scheme)) {
            writeError("WebSocket::connect: failed to determine scheme from URI " + URL);
            return false;
        }

        std::string path;

        if(!URI::getPath(URL, path)) {
            writeError("WebSocket::connect: failed to determine path from URI " + URL);
            return false;
        }

        std::string ip;
        std::string hostName;
        uint16_t port;
        
        if(!resolve(URL, ip, port, hostName)) {
            printf("Failed to resolve IP from URI %s\n", URL.c_str());
            writeError("WebSocket::connect: failed to resolve IP from URI " + URL);
            return false;
        }

        IPVersion ipVersion = detectIPVersion(ip);

        if(ipVersion == IPVersion::Invalid) {
            writeError("WebSocket::connect: invalid IP version");
            return false;
        }
        
        AddressFamily addressFamily = (ipVersion == IPVersion::IPv4) ? AddressFamily::AFInet : AddressFamily::AFInet6;

        s.fd = socket(static_cast<int>(addressFamily), SOCK_STREAM, 0);

        if(s.fd < 0) {
            writeError("WebSocket::connect: failed to create socket");
            return false;
        }

        int connectionResult = 0;

        s.addressFamily = addressFamily;

        if(ipVersion == IPVersion::IPv4) {
            s.address.ipv4.sin_family = AF_INET;
            s.address.ipv4.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &s.address.ipv4.sin_addr);
            connectionResult = ::connect(s.fd, (struct sockaddr*)&s.address.ipv4, sizeof(s.address.ipv4));
        } else {
            s.address.ipv6.sin6_family = AF_INET6;
            s.address.ipv6.sin6_port = htons(port);
            inet_pton(AF_INET6, ip.c_str(), &s.address.ipv6.sin6_addr);
            connectionResult = ::connect(s.fd, (struct sockaddr*)&s.address.ipv6, sizeof(s.address.ipv6));
        }

        if(connectionResult < 0) {
            writeError("WebSocket::connect: failed to connect");
            close();
            return false;
        }

        if(scheme == "wss") {
            sslContext = SSL_CTX_new(TLS_method());

            if(sslContext == nullptr) {
                writeError("WebSocket::connect: failed to create SSL context");
                close();
                return false;
            }

            ssl = SSL_new(sslContext);

            if(ssl == nullptr) {
                writeError("WebSocket::connect: failed to create SSL");
                close();
                return false;
            }

            SSL_set_fd(ssl, s.fd);
            
            SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)hostName.c_str());

            if (SSL_connect(ssl) != 1) {
                writeError("WebSocket::connect: failed to SSL connect");
                close();
                return false;
            }
        }

        std::string request;
        std::string webKey = generateKey();

        request += "GET " + path + " HTTP/1.1\r\n";
        request += "Host: " + hostName + "\r\n";
        request += "Upgrade: websocket\r\n";
        request += "Connection: Upgrade\r\n";
        request += "Sec-WebSocket-Key: " + webKey + "\r\n";
        request += "Sec-WebSocket-Version: 13\r\n\r\n";

        if(write(request.c_str(), request.size()) <= 0) {
            writeError("WebSocket::connect: failed to send 'Connection-Upgrade' request");
            close();
            return false;
        }

        char data[1024];
        memset(data, 0, 1024);

        if(read(data, 1024) <= 0) {
            writeError("WebSocket::connect: failed to read 'Connection-Upgrade' response");
            close();
            return false;
        }

        std::string response = std::string(data);
        auto headerLines = String::split(response, "\r\n");
        Headers headers;

        for(size_t i = 0; i < headerLines.size(); i++) {
            auto headerParts = String::split(headerLines[i], ":");
            if(headerParts.size() != 2)
                continue;
            std::string key = String::trim(headerParts[0]);
            std::string value = String::trim(headerParts[1]);
            headers[key] = value;
        }

        if(headers.count("Sec-WebSocket-Accept") == 0) {
            printf("Missing Sec-WebSocket-Accept\n");
            writeError("WebSocket::connect: missing 'Sec-WebSocket-Accept' in response");
            close();
            return false;
        }

        const std::string &acceptKey = headers["Sec-WebSocket-Accept"];

        if(!verifyKey(acceptKey, webKey)) {
            writeError("WebSocket::connect: handshake keys mismatch");
            close();
            return false;
        }

        int noDelayFlag = 1;
        setOption(IPPROTO_TCP, TCP_NODELAY, (char *)&noDelayFlag, sizeof(int));

        return true;
    }

    void WebSocket::close() {
        if(s.fd >= 0) {
        #ifdef _WIN32
            closesocket(s.fd);
        #else
            ::close(s.fd);
        #endif
            s.fd = -1;
        }
        if(ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if(sslContext) {
            SSL_CTX_free(sslContext);
            sslContext = nullptr;
        }
    }

    bool WebSocket::setOption(int level, int option, const void *value, uint32_t valueSize) {
    #ifdef _WIN32
        return setsockopt(s.fd, level, option, (char*)value, valueSize) != 0 ? false : true;
    #else
        return setsockopt(s.fd, level, option, value, valueSize) != 0 ? false : true;
    #endif
    }

    void WebSocket::setBlocking(bool isBlocking) {
    #ifdef _WIN32
        u_long mode = isBlocking ? 0 : 1; // 1 to enable non-blocking socket
        if (ioctlsocket(s.fd, FIONBIO, &mode) != 0) {
            writeError("WebSocket::connect: failed to set blocking mode");
        }
    #else
        int flags = fcntl(s.fd, F_GETFL, 0);
        if (isBlocking) {
            // Clear the O_NONBLOCK flag to set the socket to blocking mode
            fcntl(s.fd, F_SETFL, flags & ~O_NONBLOCK);
        } else {
            // Set the O_NONBLOCK flag to set the socket to non-blocking mode
            fcntl(s.fd, F_SETFL, flags | O_NONBLOCK);
        }
    #endif
    }

    Result WebSocket::send(OpCode opcode, const void *data, uint64_t size, bool masked) {
        bool first = true;

        if(data != nullptr && size == 0) {
            return Result::InvalidArgument;
        }

        Result status = Result::Ok;

        if(data != nullptr) {
            const uint64_t chunkSize = 1024;
            uint64_t totalSize = size;
            const uint8_t *pPayload = reinterpret_cast<const uint8_t*>(data);

            while (totalSize > 0) {
                uint64_t length = std::min(totalSize, chunkSize);
                OpCode opc = first ? opcode : OpCode::Continuation;
                bool fin = totalSize - length == 0;
                
                status = writeFrame(opc, fin, pPayload, length, masked);
                
                if(status != Result::Ok)
                    return status;

                pPayload += length;
                totalSize -= length;
                first = false;
            }
        } else {
            return writeFrame(opcode, true, nullptr, 0, masked);
        }

        return status;
    }

    Result WebSocket::receive() {
        Message message;

        bool messageComplete = false;

        auto isControlFrameOpcode = [] (uint8_t opcode) -> bool {
            // Check if the opcode is one of the control frame opcodes
            return (opcode == 0x8 || opcode == 0x9 || opcode == 0xA);
        };

        auto cleanUp = [] (Frame *f) -> void {
            if(f->payload)
                delete[] f->payload;
        };

        //Loop and collect frames until we get to the 'fin' frame or run into an error
        while(!messageComplete) {
            uint8_t peekData = 0;
            ssize_t peekedBytes = peek(&peekData, 1);

            //If there is no data to read we can return early
            if(peekedBytes <= 0) {
                message.destroy();
                return (peekedBytes == 0) ? Result::NoData : Result::ConnectionError;
            }

            Frame frame = {0};

            Result result = readFrame(&frame);
            
            if(result != Result::Ok) {
                message.destroy();
                return result;
            }

            OpCode opcode = static_cast<OpCode>(frame.opcode);

            switch(opcode) {
                case OpCode::Text:
                case OpCode::Binary: {
                    message.opcode = opcode;

                    if(message.chunks == nullptr) {
                        message.chunks = new MessageChunk();

                        if(message.chunks == nullptr) {
                            writeError("WebSocket::receive: message.chunks = nullptr");
                            cleanUp(&frame);
                            return Result::AllocationError;
                        }

                        message.chunks->payloadLength = frame.payloadLength;
                        message.chunks->payload = frame.payload;
                        message.chunks->next = nullptr;
                    } else {
                        //This shouldn't happen
                        cleanUp(&frame);
                    }

                    break;
                }
                case OpCode::Continuation: {
                    if(message.chunks != nullptr) {
                        MessageChunk *lastChunk = message.chunks;
                        while (lastChunk->next != nullptr) {
                            lastChunk = lastChunk->next;
                        }
                        lastChunk->next = new MessageChunk();

                        if(lastChunk->next == nullptr) {
                            writeError("WebSocket::receive: lastChunk->next = nullptr");
                            cleanUp(&frame);
                            message.destroy();
                            return Result::AllocationError;
                        }

                        lastChunk->next->payloadLength = frame.payloadLength;
                        lastChunk->next->payload = nullptr;
                        lastChunk->next->next = nullptr;
                    } else {
                        //This shouldn't happen
                        cleanUp(&frame);
                    }

                    break;
                }
                case OpCode::Close: {
                    break;
                }
                case OpCode::Ping: {
                    writeFrame(OpCode::Pong, true, nullptr, 0, true);
                    break;
                }
                case OpCode::Pong: {
                    break;
                }
                default: {
                    cleanUp(&frame);
                    message.destroy();
                    return Result::InvalidOpCode;
                }
            }

            if(frame.fin) {
                if(isControlFrameOpcode(frame.opcode)) {
                    if(frame.payload)
                        delete[] frame.payload;

                    Message m;
                    m.opcode = static_cast<OpCode>(frame.opcode);
                    if(onReceived)
                        onReceived(this, m);

                    if(message.chunks == nullptr) {
                        messageComplete = true;
                        break;
                    }
                } else {
                    if(onReceived)
                        onReceived(this, message);
                    else
                        message.destroy();
                    messageComplete = true;
                    break;
                }
            }
        }

        return Result::Ok;
    }

    ssize_t WebSocket::read(void *buffer, size_t size) {
        if(ssl)
            return SSL_read(ssl, buffer, size);
    #ifdef _WIN32
        return ::recv(s.fd, (char*)buffer, size, 0);
    #else
        return ::recv(s.fd, buffer, size, 0);
    #endif
    }



    ssize_t WebSocket::write(const void *buffer, size_t size) {
        if(ssl)
            return SSL_write(ssl, buffer, size);
    #ifdef _WIN32
        return ::send(s.fd, (char*)data, size, 0);
    #else
        return ::send(s.fd, buffer, size, 0);
    #endif
    }

    ssize_t WebSocket::peek(void *buffer, size_t size) {
        if(ssl)
            return SSL_peek(ssl, buffer, size);
    #ifdef _WIN32
        return ::recv(s.fd, (char*)buffer, size, MSG_PEEK);
    #else
        return ::recv(s.fd, buffer, size, MSG_PEEK);
    #endif
    }

    bool WebSocket::readAllBytes(void *buffer, size_t size) {
        uint8_t *ptr = static_cast<uint8_t*>(buffer);
        size_t totalRead = 0;

        while (totalRead < size) {
            ssize_t bytesRead = read(ptr + totalRead, size - totalRead);
            
            if (bytesRead < 0) {
                // An error occurred
                return false;
            } else if (bytesRead == 0) {
                // Connection closed
                return false;
            }

            totalRead += bytesRead;
        }

        return true; // All bytes read successfully
    }

    bool WebSocket::writeAllBytes(const void *buffer, size_t size) {
        const uint8_t *ptr = static_cast<const uint8_t*>(buffer);
        size_t totalSent = 0;

        while (totalSent < size) {
            ssize_t bytesSent = write(ptr + totalSent, size - totalSent);
            
            if (bytesSent < 0) {
                // An error occurred
                return false;
            } else if (bytesSent == 0) {
                // Connection closed
                return false;
            }

            totalSent += bytesSent;
        }

        return true; // All bytes sent successfully
    }

    bool WebSocket::drain(size_t size) {
        size_t totalRead = 0;
        ssize_t bytesRead;
        const size_t bufferSize = 1024;
        uint8_t buffer[bufferSize];

        while (totalRead < size) {
            size_t bytesToRead = std::min(size - totalRead, bufferSize);

            bytesRead = read(buffer, bytesToRead);

            if (bytesRead < 0) {
                return false;
            } else if (bytesRead == 0) {
                if(totalRead == size)
                    return true;
                return false;
            }

            totalRead += bytesRead;
        }

        return true;
    }

    Result WebSocket::writeFrame(OpCode opcode, bool fin, const void *payload, uint64_t payloadSize, bool applyMask) {
        uint8_t frame[32] = {0};

        size_t offset = 0;

        // 1st byte: FIN, RSV1, RSV2, RSV3, Opcode
        uint8_t firstByte = 0;
        if (fin) 
            firstByte |= 0x80;  // FIN = 1 if true
            
        firstByte |= (static_cast<uint8_t>(opcode) & 0x0F);  // Opcode (lower 4 bits)
        frame[offset++] = firstByte;

        // 2nd byte: Mask bit and Payload Length (7 bits)
        uint8_t secondByte = 0;
        if (applyMask) 
            secondByte |= 0x80;  // Mask bit set if true
            
        if (payloadSize <= 125) {
            secondByte |= static_cast<uint8_t>(payloadSize);  // Payload length (7 bits)
            frame[offset++] = secondByte;
        } else if (payloadSize > 125 && payloadSize <= 65535) {
            secondByte |= 126;  // Special case for lengths > 125 but <= 65535
            frame[offset++] = secondByte;

            uint16_t sizeNetworkOrder = static_cast<uint16_t>(payloadSize);
            hostToNetworkOrder(&sizeNetworkOrder, &frame[offset], sizeof(uint16_t));
            offset += sizeof(uint16_t);
        } else {
            secondByte |= 127;  // Special case for lengths > 65535
            frame[offset++] = secondByte;

            hostToNetworkOrder(&payloadSize, &frame[offset], sizeof(uint64_t));
            offset += sizeof(uint64_t);
        }

        // Masking Key (if applyMask is true)
        uint8_t mask[4] = {0};

        if(applyMask) {
            std::random_device rd;
            std::mt19937 generator(rd());
            std::uniform_int_distribution<int> distribution(0, 255);

            for (size_t i = 0; i < 4; ++i) {
                mask[i] = static_cast<unsigned char>(distribution(generator));
                frame[offset++] = mask[i];
            }

            // Now, handle the payload (applying the mask if necessary).
            uint8_t* payloadBytes = (uint8_t*)payload;
            for (uint64_t i = 0; i < payloadSize; ++i) {
                payloadBytes[i] = payloadBytes[i] ^ mask[i % 4];
            }
        }

        // std::cout << "\n### WriteFrame data begin ###\n";
        // dumpFrame(opcode, frame, offset);
        // std::cout << "### WriteFrame data end ###\n\n";

        if(!writeAllBytes(frame, offset))
            return Result::ConnectionError;
        
        if(payloadSize == 0)
            return Result::Ok;

        if(!writeAllBytes(payload, payloadSize))
            return Result::ConnectionError;

        return Result::Ok;
    }

    Result WebSocket::readFrame(Frame *frame) {
        uint8_t header[32] = {0};
        uint8_t frameData[32] = {0};
        size_t offset = 0;

        if(!readAllBytes(header, 2)) {
            return Result::ConnectionError;
        }

        memcpy(frameData, header, 2);
        offset += 2;

        frame->fin = (header[0] & 0x80) != 0;
        frame->opcode = header[0] & 0x0F;      // Extract Opcode (4 bits)
        bool masked = (header[1] & 0x80) != 0;
        uint8_t payloadLength = header[1] & 0x7F;
        frame->payloadLength = static_cast<uint64_t>(payloadLength);

        if (payloadLength == 126) {
            uint8_t extendedLength[2] = {0};
            
            if(!readAllBytes(extendedLength, 2)) {
                return Result::ConnectionError;
            }

            memcpy(&frameData[offset], extendedLength, 2);
            offset += 2;

            uint16_t sizeHostOrder = 0;
            networkToHostOrder(extendedLength, &sizeHostOrder, sizeof(uint16_t));
            frame->payloadLength = static_cast<uint64_t>(sizeHostOrder);
        } else if (payloadLength == 127) {
            uint8_t extendedLength[8] = {0};
            
            if(!readAllBytes(extendedLength, 8)) {
                return Result::ConnectionError;
            }

            memcpy(&frameData[offset], extendedLength, 8);
            offset += 8;

            networkToHostOrder(extendedLength, &frame->payloadLength, sizeof(uint64_t));
        }

        uint8_t mask[4] = {0};

        if(masked) {
            if(!readAllBytes(mask, 4)) {
                return Result::ConnectionError;
            }

            memcpy(&frameData[offset], mask, 8);
            offset += 4;
        }

        if(frame->payloadLength > 0) {
            //printf("Allocating memory: %zu\n", frame->payloadLength);

            frame->payload = new uint8_t[frame->payloadLength];
            
            if(frame->payload == nullptr) {
                writeError("WebSocket::readFrame: frame->payload = nullptr");
                //If we make it here, make sure to 'consume' remaining data
                drain(frame->payloadLength);
                return Result::AllocationError;
            }
            
            memset(frame->payload, 0, frame->payloadLength);
            
            if(!readAllBytes(frame->payload, frame->payloadLength)) {
                delete[] frame->payload;
                frame->payload = nullptr;
                frame->payloadLength = 0;
                return Result::ConnectionError;
            }

            if(masked) {
                for(size_t i = 0; i < frame->payloadLength; i++)
                    frame->payload[i] = frame->payload[i] ^ mask[i % 4];
            }

            if(frame->opcode == 0x1) {
                if(!isValidUTF8(frame->payload, frame->payloadLength)) {
                    delete[] frame->payload;
                    frame->payload = nullptr;
                    frame->payloadLength = 0;
                    return Result::UTF8Error;
                }
            }
        }

        // std::cout << "\n### ReadFrame data begin ###\n";
        // dumpFrame(static_cast<OpCode>(frame->opcode), frameData, offset);
        // std::cout << "### ReadFrame data end ###\n\n";

        return Result::Ok;
    }

    void WebSocket::sendBadRequest(WebSocket &connection) {
        std::string response = "HTTP/1.1 400\r\n\r\n";
        connection.write(response.c_str(), response.size());
        connection.close();
    }

    bool WebSocket::readHeader(WebSocket &connection, std::string &header) {
        const size_t maxHeaderSize = 8192;
        const size_t bufferSize = maxHeaderSize;
        std::vector<char> buffer;
        buffer.resize(bufferSize);
        size_t headerEnd = 0;
        size_t totalHeaderSize = 0;
        bool endFound = false;

        char *pBuffer = &buffer[0];

        // Peek to find the end of the header
        while (true) {
            ssize_t bytesPeeked = connection.peek(pBuffer, bufferSize);

            if(bytesPeeked > 0)
                totalHeaderSize += bytesPeeked;

            if(totalHeaderSize > maxHeaderSize) {
                printf("Header size too big: %zu\n", totalHeaderSize);
                return false;
            }

            if (bytesPeeked < 0) {
                printf("Header peek error\n");
                return false;
            }

            //Don't loop indefinitely...
            if(bytesPeeked == 0) {
                break;
            }
            
            // Look for the end of the header (double CRLF)
            const char* endOfHeader = std::search(pBuffer, pBuffer + bytesPeeked, "\r\n\r\n", "\r\n\r\n" + 4);
            if (endOfHeader != pBuffer + bytesPeeked) {
                headerEnd = endOfHeader - pBuffer + 4; // Include the length of the CRLF
                endFound = true;
                break;
            }
        }

        if(!endFound) {
            printf("Header end not found\n");
            return false;
        }

        // Now read the header
        header.resize(headerEnd);
        ssize_t bytesRead = connection.read(&header[0], headerEnd);

        if (bytesRead < 0) {
            printf("Failed to read header\n");
            return false;
        }

        if(header.size() > maxHeaderSize) {
            printf("Header is too big: %zu\n", header.size());
            return false;
        }

        return true;
    }

    bool WebSocket::readMethod(const std::string &header, HttpMethod &method) {
        std::istringstream stream(header);
        std::string m;

        // Read the first word from the header
        if (stream >> m) {
            if (m == "GET") {
                method = HttpMethod::GET;
                return true;
            } else if (m == "POST") {
                method = HttpMethod::POST;
                return true;
            } else if (m == "PUT") {
                method = HttpMethod::PUT;
                return true;
            } else if (m == "DELETE") {
                method = HttpMethod::DELETE;
                return true;
            } else if (m == "HEAD") {
                method = HttpMethod::HEAD;
                return true;
            } else if (m == "OPTIONS") {
                method = HttpMethod::OPTIONS;
                return true;
            } else if (m == "PATCH") {
                method = HttpMethod::PATCH;
                return true;
            } else if (m == "TRACE") {
                method = HttpMethod::TRACE;
                return true;
            } else if (m == "CONNECT") {
                method = HttpMethod::CONNECT;
                return true;
            } else {
                return false;
            }
        }

        return false;
    }

    bool WebSocket::readPath(const std::string &header, std::string &path) {
        std::istringstream stream(header);
        std::string method;

        // Read the first word (method)
        if (stream >> method) {
            // Read the second word (path)
            if (stream >> path) {
                return true; // Return the extracted path
            }
        }

        return false;
    }

    bool WebSocket::readHeaderFields(const std::string &header, Headers &headers) {
        auto headerLines = String::split(header, "\r\n");

        if(headerLines.size() == 0)
            return false;

        for(size_t i = 0; i < headerLines.size(); i++) {
            auto headerParts = String::split(headerLines[i], ":");
            if(headerParts.size() != 2)
                continue;
            std::string key = String::trim(headerParts[0]);
            std::string value = String::trim(headerParts[1]);
            headers[key] = value;
        }
        return true;
    }

    bool WebSocket::resolve(const std::string &uri, std::string &ip, uint16_t &port, std::string &hostname) {
        std::string scheme, host, path;

        if(!URI::getScheme(uri, scheme)) {
            printf("Failed to get scheme from URI\n");
            return false;
        }

        if(!URI::getHost(uri, host)) {
            printf("Failed to get host from URI\n");
            return false;
        }

        if(!URI::getPath(uri, path)) {
            printf("Failed to get path from URI");
            return false;
        }

        if(String::contains(host, ":")) {
            auto parts = String::split(host, ":");
            
            if(parts.size() != 2)
                return false;
            
            //Get rid of the :port part in the host
            host = parts[0];

            if(!String::parseNumber(parts[1], port))
                return false;
        } else {
            if(scheme == "wss") {
                port = 443;
            } else if(scheme == "ws") {
                port = 80;
            } else {
                return false;
            }
        }

        // Resolve the hostname to an IP address
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM; // TCP

        int status = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);

        if (status != 0) {
            printf("getaddrinfo error: %s\n", gai_strerror(status));
            return false;
        }

        hostname = host;

        for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
            void* addr;

            // Get the pointer to the address itself
            if (p->ai_family == AF_INET) { // IPv4
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                addr = &(ipv4->sin_addr);
            } else { // IPv6
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }

            // Convert the IP to a string
            char ipstr[INET6_ADDRSTRLEN];
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            ip = ipstr;
        }

        freeaddrinfo(res); // Free the linked list
        return true;
    }

    IPVersion WebSocket::detectIPVersion(const std::string &ip) {
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;

        // Try to convert to IPv4
        if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) {
            return IPVersion::IPv4;
        }

        // Try to convert to IPv6
        if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1) {
            return IPVersion::IPv6;
        }

        // If both conversions fail, return Invalid
        return IPVersion::Invalid;
    }

    static std::string base64Encode(const uint8_t *buffer, size_t size) {
        BIO* bio;
        BIO* b64;
        BUF_MEM* bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines
        BIO_write(bio, buffer, size);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        return std::string(bufferPtr->data, bufferPtr->length);
    }

    std::string WebSocket::generateKey() {
        uint8_t randomBytes[16];

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<int> distribution(0, 255);

        for (auto& byte : randomBytes) {
            byte = static_cast<unsigned char>(distribution(generator));
        }

        return base64Encode(randomBytes, 16);
    }

    std::string WebSocket::generateAcceptKey(const std::string &websocketKey) {
        const std::string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string acceptKey = websocketKey + guid;

        uint8_t hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(acceptKey.c_str()), acceptKey.size(), hash);

        return base64Encode(hash, SHA_DIGEST_LENGTH);
    }

    bool WebSocket::verifyKey(const std::string& receivedAcceptKey, const std::string& originalKey) {
        std::string expectedAcceptKey = generateAcceptKey(originalKey);
        return receivedAcceptKey == expectedAcceptKey;
    }

    bool WebSocket::isValidUTF8(const void *payload, size_t size) {
        int numBytes = 0; // Number of bytes expected in the current UTF-8 character
        unsigned char byte;
        const uint8_t *pPayload = reinterpret_cast<const uint8_t*>(payload);

        for (size_t i = 0; i < size; ++i) {
            byte = pPayload[i];

            if (numBytes == 0) {
                // Determine the number of bytes in the UTF-8 character
                if ((byte & 0x80) == 0) {
                    // 1-byte character (ASCII)
                    continue;
                } else if ((byte & 0xE0) == 0xC0) {
                    // 2-byte character
                    numBytes = 1;
                } else if ((byte & 0xF0) == 0xE0) {
                    // 3-byte character
                    numBytes = 2;
                } else if ((byte & 0xF8) == 0xF0) {
                    // 4-byte character
                    numBytes = 3;
                } else {
                    // Invalid first byte
                    return false;
                }
            } else {
                // Check continuation bytes
                if ((byte & 0xC0) != 0x80) {
                    return false; // Invalid continuation byte
                }
                numBytes--;
            }
        }

        return numBytes == 0; // Ensure all characters were complete
    }

    void WebSocket::writeError(const std::string &message) {
        if(onError)
            onError(message);
    }

    ///////////////
    /////[URI]/////
    ///////////////

    bool URI::getScheme(const std::string &uri, std::string &value) {
        std::regex schemeRegex(R"(([^:/?#]+):\/\/)");
        std::smatch match;
        if (std::regex_search(uri, match, schemeRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getHost(const std::string &uri, std::string &value) {
        std::regex hostRegex(R"(:\/\/([^/?#]+))");
        std::smatch match;
        if (std::regex_search(uri, match, hostRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getPath(const std::string &uri, std::string &value) {
        std::regex pathRegex(R"(:\/\/[^/?#]+([^?#]*))");
        std::smatch match;
        if (std::regex_search(uri, match, pathRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getQuery(const std::string &uri, std::string &value) {
        std::regex queryRegex(R"(\?([^#]*))");
        std::smatch match;
        if (std::regex_search(uri, match, queryRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getFragment(const std::string &uri, std::string &value) {
        std::regex fragmentRegex(R"(#(.*))");
        std::smatch match;
        if (std::regex_search(uri, match, fragmentRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    ///////////////
    ////[String]///
    ///////////////

    bool String::contains(const std::string &haystack, const std::string &needle) {
        return haystack.find(needle) != std::string::npos;
    }

    bool String::startsWith(const std::string &haystack, const std::string &needle) {
        if (haystack.length() >= needle.length()) 
            return (0 == haystack.compare(0, needle.length(), needle));
        return false;
    }

    bool String::endsWith(const std::string &haystack, const std::string &needle) {
        if (haystack.length() >= needle.length()) 
            return (0 == haystack.compare(haystack.length() - needle.length(), needle.length(), needle));
        return false;
    }

    std::string String::trim(const std::string &s) {
        // Find the first non-whitespace character from the beginning
        size_t start = s.find_first_not_of(" \t\n\r\f\v");

        // Find the last non-whitespace character from the end
        size_t end = s.find_last_not_of(" \t\n\r\f\v");

        // Handle the case where the string is all whitespace
        if (start == std::string::npos)
            return "";

        // Extract the substring between start and end
        return s.substr(start, end - start + 1);
    }

    std::string String::trimStart(const std::string &s) {
        size_t start = s.find_first_not_of(" \t\n\r\f\v");

        if (start == std::string::npos)
            return "";

        // Extract the substring starting from the first non-whitespace character
        return s.substr(start);
    }

    std::string String::trimEnd(const std::string &s) {
        size_t end = s.find_last_not_of(" \t\n\r\f\v");

        if (end == std::string::npos)
            return "";

        // Extract the substring from the beginning to the last non-whitespace character
        return s.substr(0, end + 1);
    }

    std::string String::toLower(const std::string &s) {
        std::string result = s;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    std::string String::toUpper(const std::string &s) {
        std::string result = s;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }

    std::vector<std::string> String::split(const std::string &s, const std::string &separator) {
        std::vector<std::string> substrings;
        size_t start = 0;
        size_t end;

        // Find all occurrences of separator and split the string
        while ((end = s.find(separator, start)) != std::string::npos) {
            substrings.push_back(s.substr(start, end - start));
            start = end + separator.length();
        }

        // Add the last part of the string after the last separator
        substrings.push_back(s.substr(start));

        return substrings;
    }
}