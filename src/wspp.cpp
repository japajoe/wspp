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
#include <regex>
#include <unordered_map>
#include <random>
#include <thread>
#include <fcntl.h>

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

namespace wspp {
#ifdef _WIN32
    static bool winsockInitialized = false;
#endif

    static void initializeWinsock2() {
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

    Socket::Socket() {
        initializeWinsock2();
        std::memset(&s, 0, sizeof(socket_t));
        s.fd = -1;
    }

    Socket::Socket(AddressFamily addressFamily) {
        initializeWinsock2();
        std::memset(&s, 0, sizeof(socket_t));
        s.fd = socket(static_cast<int>(addressFamily), SOCK_STREAM, 0);
    #ifdef _WIN32
        if(s.fd == INVALID_SOCKET)
            s.fd = -1;
    #endif
    }

    Socket::Socket(const Socket &other) {
        s = other.s;
    }

    Socket::Socket(Socket &&other) noexcept {
        s = std::move(other.s);
    }

    Socket& Socket::operator=(const Socket &other) {
        if(this != &other) {
            s = other.s;
        }
        return *this;
    }

    Socket& Socket::operator=(Socket &&other) noexcept {
        if(this != &other) {
            s = std::move(other.s);
        }
        return *this;
    }

    void Socket::close() {
    #ifdef _WIN32
        closesocket(s.fd);
    #else
        ::close(s.fd);
    #endif
        s.fd = -1;
    }
    
    bool Socket::bind(const std::string &bindAddress, uint16_t port) {
        sockaddr_in_t address = {0};
        address.sin_family = AF_INET;

        struct in_addr addr;

        if (inet_pton(AF_INET, bindAddress.c_str(), &addr) <= 0)
            return false;

        address.sin_addr.s_addr = INADDR_ANY;
        std::memcpy(&address.sin_addr.s_addr, &addr, sizeof(addr));
        
        address.sin_port = htons(port);

        std::memcpy(&s.address.ipv4, &address, sizeof(sockaddr_in_t));

        return ::bind(s.fd, (struct sockaddr*)&s.address.ipv4, sizeof(sockaddr_in_t)) == SOCKET_ERROR ? false : true;
    }

    IPVersion Socket::detectIPVersion(const std::string &ip) {
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

    bool Socket::connect(const std::string &ip, uint16_t port) {
        IPVersion version = detectIPVersion(ip);

        switch(version) {
            case IPVersion::IPv4: {
                s.address.ipv4.sin_family = AF_INET;
                s.address.ipv4.sin_port = htons(port);
                inet_pton(AF_INET, ip.c_str(), &s.address.ipv4.sin_addr);
                return ::connect(s.fd, (struct sockaddr*)&s.address.ipv4, sizeof(s.address.ipv4)) == SOCKET_ERROR ? false : true;
            }
            case IPVersion::IPv6: {
                s.address.ipv6.sin6_family = AF_INET6;
                s.address.ipv6.sin6_port = htons(port);
                inet_pton(AF_INET6, ip.c_str(), &s.address.ipv6.sin6_addr);
                return ::connect(s.fd, (struct sockaddr*)&s.address.ipv6, sizeof(s.address.ipv6)) == SOCKET_ERROR ? false : true;
            }
            default:
                return false;
        }
    }

    bool Socket::listen(int32_t backlog) {
        return ::listen(s.fd, backlog) == SOCKET_ERROR ? false : true;
    }

    bool Socket::accept(Socket &socket) {
        sockaddr_in_t clientAddr;
        uint32_t addrLen = sizeof(clientAddr);

        int clientFD = -1;

    #ifdef _WIN32
        clientFD = accept(s.fd, (struct sockaddr*)&clientAddr, (int32_t*)&addrLen);
        
        if(clientFD == INVALID_SOCKET)
            clientFD = -1;
    #else
        clientFD = ::accept(s.fd, (struct sockaddr*)&clientAddr, &addrLen);
    #endif

        if (clientFD == -1)
            return false;

        socket.s.fd = clientFD;
        std::memcpy(&socket.s.address, &clientAddr, sizeof(sockaddr_in_t));

        return true;
    }

    bool Socket::setOption(int level, int option, const void *value, uint32_t valueSize) {
    #ifdef _WIN32
        return setsockopt(s.fd, level, option, (char*)value, valueSize) != 0 ? false : true;
    #else
        return setsockopt(s.fd, level, option, value, valueSize) != 0 ? false : true;
    #endif
    }

    void Socket::setNonBlocking() {
    #ifdef _WIN32
        u_long mode = 1; // 1 to enable non-blocking socket
        if (ioctlsocket(s.fd, FIONBIO, &mode) != 0) {
            printf("Failed to set non-blocking mode\n");
        }
    #else
        int flags = fcntl(s.fd, F_GETFL, 0);
        fcntl(s.fd, F_SETFL, flags | O_NONBLOCK);
    #endif
    }

    int32_t Socket::readByte() {
        unsigned char b = 0;
    #ifdef _WIN32
        if(recv(s.fd, (char*)&b, 1, 0) > 0)
            return static_cast<int32_t>(b);
    #else
        if(recv(s.fd, &b, 1, 0) > 0)
            return static_cast<int32_t>(b);
    #endif
        return -1;
    }

    ssize_t Socket::read(void *buffer, size_t size) {
    #ifdef _WIN32
        return recv(s.fd, (char*)buffer, size, 0);
    #else
        return recv(s.fd, buffer, size, 0);
    #endif
    }

    ssize_t Socket::write(const void *buffer, size_t size) {
    #ifdef _WIN32
        return send(s.fd, (char*)data, size, 0);
    #else
        return send(s.fd, buffer, size, 0);
    #endif
    }

    ssize_t Socket::peek(void *buffer, size_t size) {
    #ifdef _WIN32
        return recv(s.fd, (char*)buffer, size, MSG_PEEK);
    #else
        return recv(s.fd, buffer, size, MSG_PEEK);
    #endif
    }

    //To do: figure out better way than just passing the ipv4 address
    ssize_t Socket::receiveFrom(void *buffer, size_t size) {
        socklen_t clientLen = sizeof(s.address.ipv4);
    #ifdef _WIN32
        return recvfrom(s.fd, (char*)buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), &clientLen);
    #else
        return recvfrom(s.fd, buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), &clientLen);
    #endif
    }

    //To do: figure out better way than just passing the ipv4 address
    ssize_t Socket::sendTo(const void *buffer, size_t size) {
        socklen_t clientLen = sizeof(s.address.ipv4);
    #ifdef _WIN32
        return sendto(s.fd, (char*)buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), clientLen);
    #else
        return sendto(s.fd, buffer, size, 0, reinterpret_cast<struct sockaddr*>(&s.address.ipv4), clientLen);
    #endif
    }

    int32_t Socket::getFileDescriptor() const {
        return s.fd;
    }

    bool Socket::isSet() const {
        return s.fd >= 0;
    }

    /////SSLCONTEXT/////
    SslContext::SslContext() {
        context = nullptr;
    }

    SslContext::SslContext(const SslContext &other) {
        context = other.context;
    }

    SslContext::SslContext(SslContext &&other) noexcept {
        context = std::exchange(other.context, nullptr);
    }

    SslContext& SslContext::operator=(const SslContext &other) {
        if(this != &other) {
            context = other.context;
        }
        return *this;
    }

    SslContext& SslContext::operator=(SslContext &&other) noexcept {
        if(this != &other) {
            context = std::exchange(other.context, nullptr);
        }
        return *this;
    }

    void SslContext::dispose() {
        if(context) {
            SSL_CTX_free(context);
            context = nullptr;
        }
    }

    SSL_CTX *SslContext::getContext() const {
        return context;
    }

    bool SslContext::isServerContext() const {
        if(!context)
            return false;
        return SSL_CTX_check_private_key(context) == 1;
    }

    bool SslContext::initialize(const char *certificatePath, const char *privateKeyPath) {
        if(context)
            return true;
        
        if(certificatePath != nullptr && privateKeyPath != nullptr) {
            context = SSL_CTX_new(TLS_server_method());

            if(context == nullptr) {
                printf("Failed to create SSL context\n");
                return false;
            }
            
            if (SSL_CTX_use_certificate_file(context, certificatePath, SSL_FILETYPE_PEM) <= 0) {
                SSL_CTX_free(context);
                context = nullptr;
                printf("Failed to use certificate file\n");
                return false;
            }

            if (SSL_CTX_use_PrivateKey_file(context, privateKeyPath, SSL_FILETYPE_PEM) <= 0) {
                SSL_CTX_free(context);
                context = nullptr;
                printf("Failed to use private key file\n");
                return false;
            }

            if (!SSL_CTX_check_private_key(context)) {
                SSL_CTX_free(context);
                context = nullptr;
                printf("Failed to check private key\n");
                return false;
            }
            return true;
        } else {
            context = SSL_CTX_new(TLS_method());
            if(context == nullptr) {
                printf("Failed to create SSL context\n");
                return false;
            }
            return true;
        }
    }

    SslStream::SslStream() {
        this->ssl = nullptr;
    }

    SslStream::SslStream(Socket socket, SslContext sslContext) {
        if(socket.isSet() && sslContext.getContext()) {
            ssl = SSL_new(sslContext.getContext());

            if(ssl == nullptr)
                throw SslException("Failed to create SSL instance");

            SSL_set_fd(ssl, socket.getFileDescriptor());

            if (SSL_accept(ssl) <= 0) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                throw SslException("Failed to SSL accept");
            }
        }
    }

    SslStream::SslStream(Socket socket, SslContext sslContext, const char *hostName) {
        if(socket.isSet() && sslContext.getContext()) {
            ssl = SSL_new(sslContext.getContext());

            if(ssl == nullptr)
                throw SslException("Failed to create SSL instance");

            SSL_set_fd(ssl, socket.getFileDescriptor());
            
            if(hostName)
                SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)hostName);

            if (SSL_connect(ssl) != 1) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = nullptr;
                throw SslException("Failed to SSL connect");
            }
        }
    }

    SslStream::SslStream(const SslStream &other) {
        ssl = other.ssl;
    }

    SslStream::SslStream(SslStream &&other) noexcept {
        ssl = std::exchange(other.ssl, nullptr);
    }

    SslStream& SslStream::operator=(const SslStream &other) {
        if(this != &other) {
            ssl = other.ssl;
        }
        return *this;
    }

    SslStream& SslStream::operator=(SslStream &&other) noexcept {
        if(this != &other) {
            ssl = std::exchange(other.ssl, nullptr);
        }
        return *this;
    }

    int32_t SslStream::readByte() {
        if(!ssl)
            return -1;
        unsigned char b = 0;
        if(SSL_read(ssl, &b, 1) > 0)
            return static_cast<int32_t>(b);
        return -1;
    }

    ssize_t SslStream::read(void *buffer, size_t size) {
        if(ssl) {
            int bytesRead = SSL_read(ssl, buffer, size);
            if(bytesRead <= 0) {
                int errorCode = SSL_get_error(ssl, bytesRead);
                printf("SSL_read error code: %d\n", errorCode);
            }
            return bytesRead;
        }
        return 0;
    }

    ssize_t SslStream::write(const void *buffer, size_t size) {
        if(ssl)
            return SSL_write(ssl, buffer, size);
        return 0;
    }

    ssize_t SslStream::peek(void *buffer, size_t size) {
        if(ssl)
            return SSL_peek(ssl, buffer, size);
        return 0;
    }

    void SslStream::close() {
        if(ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
    }

    bool SslStream::isSet() const {
        return ssl != nullptr;
    }

    NetworkStream::NetworkStream() {

    }

    NetworkStream::NetworkStream(Socket socket) {
        this->socket = socket;
    }

    NetworkStream::NetworkStream(Socket socket, SslStream ssl) {
        this->socket = socket;
        this->ssl = ssl;
    }

    NetworkStream::NetworkStream(const NetworkStream &other) {
        socket = other.socket;
        ssl = other.ssl;
    }

    NetworkStream::NetworkStream(NetworkStream &&other) noexcept {
        socket = std::move(other.socket);
        ssl = std::move(other.ssl);
    }

    NetworkStream& NetworkStream::operator=(const NetworkStream &other) {
        if(this != &other) {
            socket = other.socket;
            ssl = other.ssl;
        }
        return *this;
    }

    NetworkStream& NetworkStream::operator=(NetworkStream &&other) noexcept {
        if(this != &other) {
            socket = std::move(other.socket);
            ssl = std::move(other.ssl);
        }
        return *this;
    }

    int32_t NetworkStream::readByte() {
        if(ssl.isSet())
            return ssl.readByte();
        else
            return socket.readByte();
    }

    ssize_t NetworkStream::read(void *buffer, size_t size) {
        if(ssl.isSet())
            return ssl.read(buffer, size);
        else
            return socket.read(buffer, size);
    }

    ssize_t NetworkStream::write(const void *buffer, size_t size) {
        if(ssl.isSet())
            return ssl.write(buffer, size);
        else
            return socket.write(buffer, size);
    }

    ssize_t NetworkStream::peek(void *buffer, size_t size) {
        if(ssl.isSet())
            return ssl.peek(buffer, size);
        else
            return socket.peek(buffer, size);
    }

    void NetworkStream::close() {
        if(ssl.isSet())
            ssl.close();
        socket.close();
    }

    bool NetworkStream::isSecure() const {
        return ssl.isSet();
    }

    Message::Message() {
        opcode = OpCode_Control;
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

    WebSocket::WebSocket() {
        socket = Socket(AddressFamily::AFInet);
    }

    WebSocket::WebSocket(AddressFamily addressFamily, WebSocketOption options) {
        socket = Socket(addressFamily);

        if(options & WebSocketOption_Reuse) {
            int reuse = 1;
            socket.setOption(SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        }

        if(options & WebSocketOption_NonBlocking)
            socket.setNonBlocking();
    }

    WebSocket::WebSocket(AddressFamily addressFamily, WebSocketOption options, const std::string &certificatePath, const std::string &privateKeyPath) {
        socket = Socket(addressFamily);

        if(options & WebSocketOption_Reuse) {
            int reuse = 1;
            socket.setOption(SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        }

        if(options & WebSocketOption_NonBlocking)
            socket.setNonBlocking();

        sslContext.initialize(certificatePath.c_str(), privateKeyPath.c_str());
    }

    WebSocket::WebSocket(const WebSocket &other) {
        socket = other.socket;
        sslContext = other.sslContext;
        sslStream = other.sslStream;
        stream = other.stream;
    }

    WebSocket::WebSocket(WebSocket &&other) noexcept {
        socket = std::move(other.socket);
        sslContext = std::move(other.sslContext);
        sslStream = std::move(other.sslStream);
        stream = std::move(other.stream);
    }

    WebSocket& WebSocket::operator=(const WebSocket &other) {
        if(this != &other) {
            socket = other.socket;
            sslContext = other.sslContext;
            sslStream = other.sslStream;
            stream = other.stream;
        }
        return *this;
    }

    WebSocket& WebSocket::operator=(WebSocket &&other) noexcept {
        if(this != &other) {
            socket = std::move(other.socket);
            sslContext = std::move(other.sslContext);
            sslStream = std::move(other.sslStream);
            stream = std::move(other.stream);
        }
        return *this;
    }

    void WebSocket::close() {
        if(socket.getFileDescriptor() >= 0) {
            sslStream.close();
            sslContext.dispose();
            socket.close();
        }
    }

    bool WebSocket::bind(const std::string &address, uint16_t port) {
        return socket.bind(address, port);
    }

    bool WebSocket::connect(const std::string &url) {
        HostInfo info;

        std::string URL = url;
        if(!String::endsWith(URL, "/"))
            URL += "/";
        
        if(!resolve(URL, info.ip, info.port, info.name)) {
            printf("Failed to resolve URL %s\n", URL.c_str());
            return false;
        }

        IPVersion ipVersion = Socket::detectIPVersion(info.ip);

        switch(ipVersion) {
            case IPVersion::IPv4:
                socket = Socket(AddressFamily::AFInet);
                break;
            case IPVersion::IPv6:
                socket = Socket(AddressFamily::AFInet6);
                break;
            default:
                printf("Unsupported IP version\n");
                return false;
        }

        if(!socket.connect(info.ip, info.port)) {
            printf("Failed to connect to %s:%d\n", info.ip.c_str(), info.port);
            socket.close();
            return false;
        }

        URI uri(URL);
        std::string scheme;
        uri.getScheme(scheme);

        std::string path;
        uri.getPath(path);

        if(scheme == "wss") {
            sslContext.initialize(nullptr, nullptr);
            sslStream = SslStream(socket, sslContext, info.name.c_str());
            stream = NetworkStream(socket, sslStream);
        } else {
            stream = NetworkStream(socket);
        }

        std::string request;
        std::string webKey = generateKey();

        request += "GET " + path + " HTTP/1.1\r\n";
        request += "Host: " + info.name + "\r\n";
        request += "Upgrade: websocket\r\n";
        request += "Connection: Upgrade\r\n";
        request += "Sec-WebSocket-Key: " + webKey + "\r\n";
        request += "Sec-WebSocket-Version: 13\r\n\r\n";

        if(write(request.c_str(), request.size()) > 0) {
            char data[1024];
            memset(data, 0, 1024);

            if(read(data, 1024) > 0) {
                std::string response = std::string(data);
                auto headerLines = String::split(response, "\r\n");
                std::unordered_map<std::string,std::string> headers;

                for(size_t i = 0; i < headerLines.size(); i++) {
                    auto headerParts = String::split(headerLines[i], ":");
                    if(headerParts.size() != 2)
                        continue;
                    std::string key = String::trim(headerParts[0]);
                    std::string value = String::trim(headerParts[1]);
                    headers[key] = value;
                }

                if(headers.count("Sec-WebSocket-Accept") > 0) {
                    const std::string &acceptKey = headers["Sec-WebSocket-Accept"];

                    if(!verifyKey(acceptKey, webKey)) {
                        printf("Handshake keys mismatch!\n");
                        close();
                        return false;
                    }
                } else {
                    printf("Handshake failed\n");
                    close();
                    return false;
                }

                // for(const auto &item : headers) {
                //     printf("%s: %s\n", item.first.c_str(), item.second.c_str());
                // }
            }
        }

        return true;
    }

    bool WebSocket::listen(int32_t backlog) {
        return socket.listen(backlog);
    }

    bool WebSocket::accept(WebSocket &webSocket) {
        if(!this->socket.accept(webSocket.socket))
            return false;

        if(sslContext.isServerContext()) {
            try {
                webSocket.sslStream = SslStream(webSocket.socket, sslContext);
                webSocket.stream = NetworkStream(webSocket.socket, webSocket.sslStream);
            } catch (const SslException &ex) {
                webSocket.close();
                printf("Failed to create SslStream\n");
                return false;
            }
        } else {
            webSocket.stream = NetworkStream(webSocket.socket);
        }

        std::string header;

        if(!readHeader(webSocket, header)) {
            printf("Failed to read header\n");
            sendBadRequest(webSocket);
            return false;
        }

        HttpMethod method;

        try {
            method = readMethod(header);
        } catch (const std::invalid_argument& e) {
            printf("Failed to read method\n");
            sendBadRequest(webSocket);
            return false;
        }

        std::string path;

        try {
            path = readPath(header);
        } catch (const std::invalid_argument& e) {
            printf("Failed to read path\n");
            sendBadRequest(webSocket);
            return false;
        }

        Headers headers = readHeaderFields(header);

        if(method != HttpMethod::GET) {
            printf("Failed to read header fields\n");
            sendBadRequest(webSocket);
            return false;
        }

        const std::vector<std::string> requiredHeaders = {
            "Upgrade", "Connection", "Sec-WebSocket-Version", "Sec-WebSocket-Key"
        };

        for (const auto &key : requiredHeaders) {
            if (headers.count(key) == 0) {
                printf("Failed to find required header key: %s\n", key.c_str());
                sendBadRequest(webSocket);
                return false;
            }
        }

        std::string upgrade = headers["Upgrade"];
        std::string connection = headers["Connection"];
        std::string version = headers["Sec-WebSocket-Version"];
        std::string webKey = headers["Sec-WebSocket-Key"];

        if(upgrade != "websocket") {
            printf("Failed to find websocket\n");
            sendBadRequest(webSocket);
            return false;
        }

        if(!String::contains(connection, "Upgrade")) {
            printf("Failed to find upgrade request\n");
            sendBadRequest(webSocket);
            return false;
        }

        if(version != "13") {
            printf("Version mismatch\n");
            sendBadRequest(webSocket);
            return false;
        }

        std::string acceptKey = generateAcceptKey(webKey);

        std::string response = "HTTP/1.1 101 Switching Protocols\r\n";
        response += "Upgrade: websocket\r\n";
        response += "Connection: Upgrade\r\n";
        response += "Server: Testing\r\n";
        response += "Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n";

        ssize_t sentBytes = webSocket.write(response.data(), response.size());
        
        return true;
    }

    bool WebSocket::setOption(int level, int option, const void *value, uint32_t valueSize) {
        return socket.setOption(level, option, value, valueSize);
    }

    void WebSocket::setNonBlocking() {
        socket.setNonBlocking();
    }

    ssize_t WebSocket::read(void *buffer, size_t size) {
        return stream.read(buffer, size);
    }

    ssize_t WebSocket::write(const void *buffer, size_t size) {
        return stream.write(buffer, size);
    }

    ssize_t WebSocket::peek(void *buffer, size_t size) {
        return stream.peek(buffer, size);
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

    HttpMethod WebSocket::readMethod(const std::string &header) {
        std::istringstream stream(header);
        std::string method;

        // Read the first word from the header
        if (stream >> method) {
            if (method == "GET") {
                return HttpMethod::GET;
            } else if (method == "POST") {
                return HttpMethod::POST;
            } else if (method == "PUT") {
                return HttpMethod::PUT;
            } else if (method == "DELETE") {
                return HttpMethod::DELETE;
            } else if (method == "HEAD") {
                return HttpMethod::HEAD;
            } else if (method == "OPTIONS") {
                return HttpMethod::OPTIONS;
            } else if (method == "PATCH") {
                return HttpMethod::PATCH;
            } else if (method == "TRACE") {
                return HttpMethod::TRACE;
            } else if (method == "CONNECT") {
                return HttpMethod::CONNECT;
            } else {
                throw std::invalid_argument("Unknown HTTP method: " + method);
            }
        }

        throw std::invalid_argument("Invalid header format: " + header);
    }

    std::string WebSocket::readPath(const std::string &header) {
        std::istringstream stream(header);
        std::string method;
        std::string path;

        // Read the first word (method)
        if (stream >> method) {
            // Read the second word (path)
            if (stream >> path) {
                return path; // Return the extracted path
            }
        }

        throw std::invalid_argument("Invalid header format: " + header);
    }

    Headers WebSocket::readHeaderFields(const std::string &header) {
        auto headerLines = String::split(header, "\r\n");
        std::unordered_map<std::string,std::string> headers;

        for(size_t i = 0; i < headerLines.size(); i++) {
            auto headerParts = String::split(headerLines[i], ":");
            if(headerParts.size() != 2)
                continue;
            std::string key = String::trim(headerParts[0]);
            std::string value = String::trim(headerParts[1]);
            headers[key] = value;
        }
        return headers;
    }

    void WebSocket::sendBadRequest(WebSocket webSocket) {
        std::string response = "HTTP/1.1 400\r\n\r\n";
        webSocket.write(response.c_str(), response.size());
        webSocket.close();
    }

    bool WebSocket::send(OpCode opcode, const void *payload, size_t payloadSize, bool masked) {
        bool first = true;
        uint64_t chunkSize = 100;
        const uint8_t *pPayload = reinterpret_cast<const uint8_t*>(payload);

        while (payloadSize > 0) {
            uint64_t length = payloadSize;
            if (length > chunkSize) {
                length = chunkSize;
            }

            if (!writeFrame(
                        first ? opcode : OpCode_Control,
                        payloadSize - length == 0,
                        pPayload,
                        length, masked)) {
                return false;
            }

            pPayload += length;
            payloadSize -= length;
            first = false;
        }

        return true;
    }

    bool WebSocket::sendPing() {
        return writeFrame(OpCode_Ping, true, nullptr, 0, true);
    }

    bool WebSocket::receive(Message *message) {
        uint8_t peekData = 0;
        ssize_t peekedBytes = 0;

        peekedBytes = peek(&peekData, 1);

        if(peekedBytes <= 0)
            return false;

        auto isControl = [] (uint8_t opcode) -> bool {
            return 0x8 <= opcode && opcode <= 0xF;
        };

        MessageChunk *end = nullptr;

        Frame frame = {0};
        bool ret = readFrame(&frame);

        while (ret) {
            if (isControl(frame.opcode)) {
                switch (frame.opcode) {
                    case OpCode_Close: {
                        message->chunks = nullptr;
                        message->opcode = OpCode_Close;
                        return true;
                    }
                    break;
                    case OpCode_Ping:
                        if(!writeFrame(OpCode_Pong, true, nullptr, 0, true))
                            goto error;
                        break;
                    case OpCode_Pong:
                        message->chunks = nullptr;
                        message->opcode = OpCode_Pong;
                        return true;
                    default: {
                        // Ignore any other control frames for now
                        break;
                    }
                }

                delete[] frame.payload;
                frame.payload = nullptr;
            } else {
                // TODO: cws_read_message does not verify that the message starts with non CONT frame (does it have to start with non-CONT frame)?
                // TODO: cws_read_message does not verify that any non-fin "continuation" frames have the CONT opcode
                if (end == nullptr) {
                    end = new MessageChunk();
                    if (end == nullptr) {
                        goto error;
                    }
                    memset(end, 0, sizeof(*end));
                    end->payload = frame.payload;
                    end->payloadLength = frame.payloadLength;
                    message->chunks = end;
                    message->opcode = (OpCode)frame.opcode;
                } else {
                    end->next = new MessageChunk();
                    if (end->next == nullptr) {
                        goto error;
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

        if (!ret) {
            goto error;
        }

        return true;
    error:
        message->destroy();
        if (frame.payload) {
            delete[] frame.payload;
            frame.payload = nullptr;
        }
        return false;
    }

    bool WebSocket::writeFrame(OpCode opcode, bool fin, const void *payload, uint64_t payloadSize, bool applyMask) {
        uint8_t data = opcode;

        // NOTE: FIN is always set
        if (fin) {
            data |= (1 << 7);
        }
        if (write(&data, 1) < 0) {
            return false;
        }

        // Send masked and payload length
        // TODO: do we need to reverse the bytes on a machine with a different endianess than x86?
        // NOTE: client frames are always masked
        if (payloadSize < 126) {
            uint8_t data = applyMask ? (1 << 7) : 0;
            data |= (uint8_t)payloadSize;

            if (write(&data, sizeof(data)) <= 0) {
                return false;
            }
        } else if (payloadSize <= UINT16_MAX) {
            uint8_t data = applyMask ? (1 << 7) : 0;
            data |= (uint8_t)126;

            if (write(&data, sizeof(data)) <= 0) {
                return false;
            }

            uint8_t len[2] = {
                static_cast<uint8_t>((payloadSize >> (8 * 1)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 0)) & 0xFF)
            };

            if (write(&len, sizeof(len)) <= 0) {
                return false;
            }
        } else if (payloadSize > UINT16_MAX) {
            uint8_t data = applyMask ? (1 << 7) : 0;
            data |= (uint8_t)127;

            uint8_t len[8] = {
                static_cast<uint8_t>((payloadSize >> (8 * 7)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 6)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 5)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 4)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 3)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 2)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 1)) & 0xFF),
                static_cast<uint8_t>((payloadSize >> (8 * 0)) & 0xFF)
            };

            if (write(&data, sizeof(data)) <= 0) {
                return false;
            }

            if (write(&len, sizeof(len)) <= 0) {
                return false;
            }
        }

        uint8_t mask[4] = {0};

        if(applyMask) {
            // Generate and send mask
            for (size_t i = 0; i < 4; ++i) {
                mask[i] = rand() % 0x100;
            }

            if (write(mask, sizeof(mask)) <= 0) {
                return false;
            }
        }

        // Mask the payload and send it
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
            }

            if (write(chunk, chunk_size) <= 0) {
                return false;
            }
        }

        return true;
    }

    bool WebSocket::readFrame(Frame *frame) {
        #define FIN(header)         ((header)[0] >> 7)
        #define OPCODE(header)      ((header)[0] & 0xF)
        #define MASK(header)        ((header)[1] >> 7)
        #define PAYLOAD_LEN(header) ((header)[1] & 0x7F)

        uint8_t header[2] = {0};

        // Read the header
        if (read(header, sizeof(header)) <= 0) {
            //printf("Failed to read frame header\n");
            return false;
        }

        uint64_t payloadLength = 0;

        // Parse the payload length
        // TODO: do we need to reverse the bytes on a machine with a different endianess than x86?
        uint8_t len = PAYLOAD_LEN(header);
        switch (len) {
            case 126: {
                uint8_t ext_len[2] = {0};
                if (read(&ext_len, sizeof(ext_len)) <= 0) {
                    //printf("Failed to read payload length (1)\n");
                    return false;
                }

                for (size_t i = 0; i < sizeof(ext_len); ++i) {
                    payloadLength = (payloadLength << 8) | ext_len[i];
                }
            }
            break;
            case 127: {
                uint8_t ext_len[8] = {0};
                if (read(&ext_len, sizeof(ext_len)) <= 0) {
                    //printf("Failed to read payload length (2)\n");
                    return false;
                }

                for (size_t i = 0; i < sizeof(ext_len); ++i) {
                    payloadLength = (payloadLength << 8) | ext_len[i];
                }
            }
            break;
            default:
                payloadLength = len;
        }

        // Read the mask
        // TODO: the server may not send masked frames
        uint8_t mask[4] = {0};
        bool masked = MASK(header);

        if (masked) {
            if (read(&mask, 4) <= 0) {
                //printf("Failed to read mask\n");
                return false;
            }
        }

        // Read the payload
        frame->fin = FIN(header);
        frame->opcode = OPCODE(header);
        frame->payloadLength = payloadLength;

        if (frame->payloadLength > 0) {
            frame->payload = new uint8_t[payloadLength];
            if (frame->payload == nullptr) {
                //printf("Failed to allocate memory for payload\n");
                return false;
            }
            memset(frame->payload, 0, payloadLength);

            // TODO: cws_read_frame does not handle when cws->read didn't read the whole payload
            if (read(frame->payload, frame->payloadLength) <= 0) {
                delete[] frame->payload;
                frame->payload = nullptr;
                //printf("Failed to read payload\n");
                return false;
            }

            if(masked) {
                for(size_t i = 0; i < frame->payloadLength; i++)
                    frame->payload[i] = frame->payload[i] ^ mask[i % 4];
            }

            if(frame->opcode == 0x1) {
                if(!isValidUTF8(frame->payload, frame->payloadLength)) {
                    delete[] frame->payload;
                    frame->payload = nullptr;
                    //printf("Detected invalid UTF-8\n");
                    return false;
                }
            }
        }

        return true;
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

        // Compute SHA-1 hash
        uint8_t hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(acceptKey.c_str()), acceptKey.size(), hash);

        // Encode the hash in Base64
        return base64Encode(hash, SHA_DIGEST_LENGTH);
    }

    bool WebSocket::verifyKey(const std::string& receivedAcceptKey, const std::string& originalKey) {
        std::string expectedAcceptKey = generateAcceptKey(originalKey);
        return receivedAcceptKey == expectedAcceptKey;
    }

    bool WebSocket::resolve(const std::string &uri, std::string &ip, uint16_t &port, std::string &hostname) {
        enum class Mode {
            Insecure,
            Secure,
            Invalid
        };

        Mode mode = Mode::Invalid;
        size_t protocolLength = 6;

        // Check if the URI starts with "wss://" or "ws://"
        if (uri.substr(0, 6) == "wss://") {
            mode = Mode::Secure;
            protocolLength = 6;
        } else if(uri.substr(0, 5) == "ws://") {
            mode = Mode::Insecure;
            protocolLength = 5;
        } else {
            printf("Invalid URI: %s\n", uri.c_str());
            return false;
        }

        // Extract the hostname and path
        std::string::size_type pos = uri.find('/', protocolLength); // Find the first '/' after "wss://"
        std::string host = uri.substr(protocolLength, pos - protocolLength); // Extract the hostname
        std::string path = uri.substr(pos); // Extract the path

        // Default port for wss
        if(mode == Mode::Secure)
            port = 443;
        else
            port = 80;

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

    URI::URI(const std::string &uriString) {
        this->uri = uriString;
    }

    bool URI::getScheme(std::string &value) {
        std::regex schemeRegex(R"(([^:/?#]+):\/\/)");
        std::smatch match;
        if (std::regex_search(uri, match, schemeRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getHost(std::string &value) {
        std::regex hostRegex(R"(:\/\/([^/?#]+))");
        std::smatch match;
        if (std::regex_search(uri, match, hostRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getPath(std::string &value)
    {
        std::regex pathRegex(R"(:\/\/[^/?#]+([^?#]*))");
        std::smatch match;
        if (std::regex_search(uri, match, pathRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getQuery(std::string &value) {
        std::regex queryRegex(R"(\?([^#]*))");
        std::smatch match;
        if (std::regex_search(uri, match, queryRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

    bool URI::getFragment(std::string &value) {
        std::regex fragmentRegex(R"(#(.*))");
        std::smatch match;
        if (std::regex_search(uri, match, fragmentRegex)) {
            value = match[1];
            return true;
        }
        return false;
    }

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