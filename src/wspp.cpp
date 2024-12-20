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

namespace wspp {
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

    WebSocket::WebSocket() {
        memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
        s.addressFamily = AddressFamily::AFInet;
        sslContext = nullptr;
        ssl = nullptr;
    }

    WebSocket::WebSocket(AddressFamily addressFamily) {
        memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
        s.addressFamily = addressFamily;
        sslContext = nullptr;
        ssl = nullptr;
    }

    WebSocket::WebSocket(AddressFamily addressFamily, const std::string &certificatePath, const std::string &privateKeyPath) {
        memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
        s.addressFamily = addressFamily;
        sslContext = nullptr;
        ssl = nullptr;

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
    }

    WebSocket::WebSocket(WebSocket &&other) noexcept {
        memcpy(&s, &other.s, sizeof(other.s));
        other.s.fd = -1;
        sslContext = std::exchange(other.sslContext, nullptr);
        ssl = std::exchange(other.ssl, nullptr);
    }

    WebSocket::~WebSocket() {
        close();
    }

    WebSocket& WebSocket::operator=(const WebSocket &other) {
        if(this != &other) {
            s = other.s;
            sslContext = other.sslContext;
            ssl = other.ssl;
        }
        return *this;
    }

    WebSocket& WebSocket::operator=(WebSocket &&other) noexcept {
        if(this != &other) {
            memcpy(&s, &other.s, sizeof(other.s));
            other.s.fd = -1;
            sslContext = std::exchange(other.sslContext, nullptr);
            ssl = std::exchange(other.ssl, nullptr);
        }
        return *this;
    }

    bool WebSocket::bind(const std::string &bindAddress, uint16_t port) {
        if(s.fd < 0) {
            int32_t newfd = ::socket(static_cast<int>(s.addressFamily), SOCK_STREAM, 0);
            if(newfd < 0)
                return false;
            s.fd = newfd;
        }

        if (s.addressFamily == AddressFamily::AFInet) {
            sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            address.sin_addr.s_addr = INADDR_ANY;

            // If you want to bind to a specific address, use inet_pton
            if (inet_pton(AF_INET, bindAddress.c_str(), &address.sin_addr) <= 0) {
                return false;
            }

            memcpy(&s.address.ipv4, &address, sizeof(sockaddr_in));

            int reuse = 1;
            setOption(SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            return ::bind(s.fd, (struct sockaddr*)&address, sizeof(address)) == 0;
        } else if (s.addressFamily == AddressFamily::AFInet6) {
            sockaddr_in6 address = {0};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(port);
            address.sin6_addr = in6addr_any;

            // If you want to bind to a specific address, use inet_pton
            if (inet_pton(AF_INET6, bindAddress.c_str(), &address.sin6_addr) <= 0) {
                return false;
            }

            memcpy(&s.address.ipv4, &address, sizeof(sockaddr_in6));

            int reuse = 1;
            setOption(SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            return ::bind(s.fd, (struct sockaddr*)&address, sizeof(address)) == 0;
        }

        return false;
    }

    bool WebSocket::listen(int32_t backlog) {
        if(s.fd < 0)
            return false;
        return ::listen(s.fd, backlog) == 0;
    }

    bool WebSocket::accept(WebSocket &client) {
        if(s.fd < 0) {
            printf("Socket is not initialized\n");
            return false;
        }

        if(client.s.fd >= 0) {
            printf("Can not accept socket because it is already initialized\n");
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
            //printf("Failed to accept socket: %s\n", strerror(errno));
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
            client.close();
            return false;
        }

        if(sslContext) {
            client.ssl = SSL_new(sslContext);
            
            if(client.ssl == nullptr) {
                printf("Failed to create SSL\n");
                client.close();
                return false;
            }

            SSL_set_fd(client.ssl, client.s.fd);

            if (SSL_accept(client.ssl) <= 0) {
                printf("Failed to set SSL file descriptor\n");
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
            printf("Failed to read header\n");
            sendBadRequest(client);
            return false;
        }

        if(!readMethod(header, method)) {
            printf("Failed to read method from header\n");
            sendBadRequest(client);
            return false;
        }
        
        if(!readPath(header, path)) {
            printf("Failed to read path from header\n");
            sendBadRequest(client);
            return false;
        }

        Headers headers;
        
        if(!readHeaderFields(header, headers)) {
            printf("Failed to read header fields\n");
            sendBadRequest(client);
            return false;
        }

        if(method != HttpMethod::GET) {
            printf("Unsupported method\n");
            sendBadRequest(client);
            return false;
        }

        const std::vector<std::string> requiredHeaders = {
            "Upgrade", "Connection", "Sec-WebSocket-Version", "Sec-WebSocket-Key"
        };

        for (const auto &key : requiredHeaders) {
            if (headers.count(key) == 0) {
                printf("Missing required header fieldL %s\n", key.c_str());
                sendBadRequest(client);
                return false;
            }
        }

        std::string upgrade = headers["Upgrade"];
        std::string connection = headers["Connection"];
        std::string version = headers["Sec-WebSocket-Version"];
        std::string webKey = headers["Sec-WebSocket-Key"];

        if(upgrade != "websocket") {
            printf("Failed to find websocket\n");
            sendBadRequest(client);
            return false;
        }

        if(!String::contains(connection, "Upgrade")) {
            printf("Failed to find upgrade request\n");
            sendBadRequest(client);
            return false;
        }

        if(version != "13") {
            printf("Version mismatch\n");
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
            printf("Failed to send handshake response\n");
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
            printf("Failed to determine scheme from URI %s\n", URL.c_str());
            return false;
        }

        std::string path;

        if(!URI::getPath(URL, path)) {
            printf("Failed to determine path from URI %s\n", URL.c_str());
            return false;
        }

        std::string ip;
        std::string hostName;
        uint16_t port;
        
        if(!resolve(URL, ip, port, hostName)) {
            printf("Failed to resolve IP from URI %s\n", URL.c_str());
            return false;
        }

        IPVersion ipVersion = detectIPVersion(ip);

        if(ipVersion == IPVersion::Invalid) {
            printf("Invalid IP version\n");
            return false;
        }
        
        AddressFamily addressFamily = (ipVersion == IPVersion::IPv4) ? AddressFamily::AFInet : AddressFamily::AFInet6;

        s.fd = socket(static_cast<int>(addressFamily), SOCK_STREAM, 0);

        if(s.fd < 0) {
            printf("Failed to create socket\n");
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
            printf("Failed to connect\n");
            close();
            return false;
        }

        if(scheme == "wss") {
            sslContext = SSL_CTX_new(TLS_method());

            if(sslContext == nullptr) {
                printf("Failed to create SSL context\n");
                close();
                return false;
            }

            ssl = SSL_new(sslContext);

            if(ssl == nullptr) {
                printf("Failed to create SSL\n");
                close();
                return false;
            }

            SSL_set_fd(ssl, s.fd);
            
            SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)hostName.c_str());

            if (SSL_connect(ssl) != 1) {
                printf("Failed to SSL connect\n");
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
            printf("Failed to send upgrade request\n");
            close();
            return false;
        }

        char data[1024];
        memset(data, 0, 1024);

        if(read(data, 1024) <= 0) {
            printf("Failed to read upgrade response\n");
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
            close();
            return false;
        }

        const std::string &acceptKey = headers["Sec-WebSocket-Accept"];

        if(!verifyKey(acceptKey, webKey)) {
            printf("Handshake keys mismatch!\n");
            close();
            return false;
        }

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
            printf("Failed to set blocking mode\n");
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

    Result WebSocket::send(OpCode opcode, const void *data, size_t size, bool masked) {
        bool first = true;

        Result status = Result::Ok;

        if(data && size > 0) {
            uint64_t chunkSize = 100;
            const uint8_t *pPayload = reinterpret_cast<const uint8_t*>(data);

            while (size > 0) {
                uint64_t length = std::min(size, chunkSize);
                OpCode opc = first ? opcode : OpCode::Continuation;
                bool fin = size - length == 0;
                
                status = writeFrame(opc, fin, pPayload, length, masked);
                
                if(status != Result::Ok)
                    return status;

                pPayload += length;
                size -= length;
                first = false;
            }
        } else {
            return writeFrame(opcode, true, nullptr, 0, masked);
        }

        return status;
    }

    Result WebSocket::receive(Message *message) {
        uint8_t peekData = 0;
        ssize_t peekedBytes = 0;

        peekedBytes = peek(&peekData, 1);

        if(peekedBytes <= 0) {
            return (peekedBytes == 0) ? Result::NoData : Result::ConnectionError;
        }

        auto isControl = [] (uint8_t opcode) -> bool {
            return 0x8 <= opcode && opcode <= 0xF;
        };

        MessageChunk *end = nullptr;

        Frame frame = {0};
        Result ret = readFrame(&frame);

        while (ret == Result::Ok) {
            if (isControl(frame.opcode)) {
                OpCode opcode = static_cast<OpCode>(frame.opcode);
                switch (opcode) {
                    case OpCode::Close: {
                        message->destroy();
                        if (frame.payload) {
                            delete[] frame.payload;
                            frame.payload = nullptr;
                        }
                        message->chunks = nullptr;
                        message->opcode = OpCode::Close;
                        return Result::Ok;
                    }
                    case OpCode::Ping: {
                        message->destroy();
                        if (frame.payload) {
                            delete[] frame.payload;
                            frame.payload = nullptr;
                        }
                        message->chunks = nullptr;
                        message->opcode = OpCode::Ping;
                        return writeFrame(OpCode::Pong, true, nullptr, 0, true);
                    }
                    case OpCode::Pong: {
                        message->destroy();
                        if (frame.payload) {
                            delete[] frame.payload;
                            frame.payload = nullptr;
                        }
                        message->chunks = nullptr;
                        message->opcode = OpCode::Pong;
                        return Result::Ok;
                    }
                    default: {
                        // Ignore any other control frames for now
                        break;
                    }
                }

                if(frame.payload) {
                    delete[] frame.payload;
                    frame.payload = nullptr;
                }

            } else {
                // TODO: cws_read_message does not verify that the message starts with non CONT frame (does it have to start with non-CONT frame)?
                // TODO: cws_read_message does not verify that any non-fin "continuation" frames have the CONT opcode
                if (end == nullptr) {
                    end = new MessageChunk();
                    if (end == nullptr) {
                        message->destroy();
                        if (frame.payload) {
                            delete[] frame.payload;
                            frame.payload = nullptr;
                        }
                        return Result::AllocationError;
                    }
                    memset(end, 0, sizeof(*end));
                    end->payload = frame.payload;
                    end->payloadLength = frame.payloadLength;
                    message->chunks = end;
                    message->opcode = (OpCode)frame.opcode;
                } else {
                    end->next = new MessageChunk();
                    if (end->next == nullptr) {
                        message->destroy();
                        if (frame.payload) {
                            delete[] frame.payload;
                            frame.payload = nullptr;
                        }
                        return Result::AllocationError;
                    }
                    memset(end->next, 0, sizeof(*end->next));
                    end->next->payload = frame.payload;
                    end->next->payloadLength = frame.payloadLength;
                    end = end->next;
                }

                // The frame's payload has been moved to the message chunk (moved as in C++ moved,
                // the ownership of the payload belongs to message now)
                frame.payload = nullptr;
                frame.payloadLength = 0;

                if (frame.fin) {
                    break;
                }
            }

            ret = readFrame(&frame);
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

    Result WebSocket::writeFrame(OpCode opcode, bool fin, const void *payload, uint64_t payloadSize, bool applyMask) {
        size_t body_offset = 0;
        uint8_t frame[32] = {0};

        if(fin) {
            frame[0] = static_cast<uint8_t>(1 << 7);
        }

        frame[0] |= static_cast<uint8_t>(opcode);
        
        if(applyMask) {
            frame[1] = static_cast<uint8_t>(1 << 7);
        }
        if(payloadSize < 126) {
            frame[1] |= static_cast<uint8_t>(payloadSize);
            body_offset = 2;
        } else if(payloadSize <= 0xFFFF) {
            frame[1] |= 126;
            frame[2] = static_cast<uint8_t>(payloadSize >> 8);
            frame[3] = static_cast<uint8_t>(payloadSize & 0xFF);
            body_offset = 4;
        } else {
            frame[1] |= 127;
            frame[2] = static_cast<uint8_t>((payloadSize >> 56) & 0xFF);
            frame[3] = static_cast<uint8_t>((payloadSize >> 48) & 0xFF);
            frame[4] = static_cast<uint8_t>((payloadSize >> 40) & 0xFF);
            frame[5] = static_cast<uint8_t>((payloadSize >> 32) & 0xFF);
            frame[6] = static_cast<uint8_t>((payloadSize >> 24) & 0xFF);
            frame[7] = static_cast<uint8_t>((payloadSize >> 16) & 0xFF);
            frame[8] = static_cast<uint8_t>((payloadSize >>  8) & 0xFF);
            frame[9] = static_cast<uint8_t>((payloadSize)       & 0xFF);
            body_offset = 10;
        }

        uint8_t mask[4] = {0};

        if(applyMask) {
            std::random_device rd;
            std::mt19937 generator(rd());
            std::uniform_int_distribution<int> distribution(0, 255);

            for (size_t i = 0; i < 4; ++i) {
                mask[i] = static_cast<unsigned char>(distribution(generator));
            }

            memcpy(&frame[body_offset], mask, 4);

            body_offset += 4;
        }

        //send header
        ssize_t bytesWritten = 0;
        bytesWritten = write(frame, body_offset);

        if(bytesWritten <= 0) {
            printf("Error %s\n", strerror(errno));

            if(bytesWritten == 0)
                return Result::NoData;
            else
                return Result::ConnectionError;
        }

        //send payload
        uint64_t i = 0;
        const uint8_t *pPayload = reinterpret_cast<const uint8_t*>(payload);

        while (i < payloadSize) {
            uint8_t chunk[1024];
            uint64_t chunk_size = 0;

            if(applyMask) {
                while (i < payloadSize && chunk_size < sizeof(chunk)) {
                    chunk[chunk_size] = pPayload[i] ^ mask[i % 4];
                    chunk_size += 1;
                    i += 1;
                }
            } else {
                while (i < payloadSize && chunk_size < sizeof(chunk)) {
                    chunk[chunk_size] = pPayload[i];
                    chunk_size += 1;
                    i += 1;
                }
            }

            bytesWritten = write(chunk, chunk_size);

            if(bytesWritten <= 0) {                
                return Result::ConnectionError;
            }
        }
        
        return Result::Ok;
    }

    Result WebSocket::readFrame(Frame *frame) {
        #define FIN(header)         ((header)[0] >> 7)
        #define OPCODE(header)      ((header)[0] & 0xF)
        #define MASK(header)        ((header)[1] >> 7)
        #define PAYLOAD_LEN(header) ((header)[1] & 0x7F)

        uint8_t header[2] = {0};

        // Read the header
        ssize_t bytesRead = read(header, sizeof(header));

        if (bytesRead <= 0) {
            if(bytesRead == 0)
                return Result::NoData;
            else
                return Result::ConnectionError;
        }

        frame->fin = FIN(header);
        frame->opcode = OPCODE(header);

        uint64_t payloadLength = 0;

        // Parse the payload length
        // TODO: do we need to reverse the bytes on a machine with a different endianess than x86?
        uint8_t len = PAYLOAD_LEN(header);
        
        switch (len) {
            case 126: {
                uint8_t ext_len[2] = {0};

                bytesRead = read(&ext_len, sizeof(ext_len));

                if (bytesRead <= 0) {
                    if(bytesRead == 0)
                        return Result::NoData;
                    else
                        return Result::ConnectionError;
                }

                for (size_t i = 0; i < sizeof(ext_len); ++i) {
                    payloadLength = (payloadLength << 8) | ext_len[i];
                }

                break;
            }
            case 127: {
                uint8_t ext_len[8] = {0};

                bytesRead = read(&ext_len, sizeof(ext_len));

                if (bytesRead <= 0) {
                    if(bytesRead == 0)
                        return Result::NoData;
                    else
                        return Result::ConnectionError;
                }

                for (size_t i = 0; i < sizeof(ext_len); ++i) {
                    payloadLength = (payloadLength << 8) | ext_len[i];
                }

                break;
            }
            default:
                payloadLength = len;
        }

        frame->payloadLength = payloadLength;

        // Read the mask
        uint8_t mask[4] = {0};
        bool masked = MASK(header);

        if (masked) {
            bytesRead = read(mask, 4);

            if (bytesRead <= 0) {
                if(bytesRead == 0)
                    return Result::NoData;
                else
                    return Result::ConnectionError;
            }
        }

        // Read the payload
        if (frame->payloadLength > 0) {
            frame->payload = new uint8_t[payloadLength];

            if (frame->payload == nullptr) {
                return Result::AllocationError;
            }

            memset(frame->payload, 0, payloadLength);

            // TODO: cws_read_frame does not handle when cws->read didn't read the whole payload
            bytesRead = read(frame->payload, frame->payloadLength);

            if (bytesRead <= 0) {
                delete[] frame->payload;
                frame->payload = nullptr;

                if(bytesRead == 0)
                    return Result::NoData;
                else
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
                    return Result::UTF8Error;
                }
            }
        }

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