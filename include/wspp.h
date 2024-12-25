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

#ifndef WSPP_WSPP_HPP
#define WSPP_WSPP_HPP

#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <chrono>
#include <functional>

#ifdef _WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#include <openssl/ssl.h>

namespace wspp {
    enum class AddressFamily : int {
        AFInet = AF_INET,
        AFInet6 = AF_INET6
    };

    enum class IPVersion {
        IPv4,
        IPv6,
        Invalid
    };

    typedef struct sockaddr_in sockaddr_in_t;
    typedef struct sockaddr_in6 sockaddr_in6_t;

    typedef union {
        sockaddr_in_t ipv4;
        sockaddr_in6_t ipv6;
    } socket_address_t;

    typedef struct {
        int32_t fd;
        socket_address_t address;
        AddressFamily addressFamily;
    } socket_t;

    enum class HttpMethod {
        GET,
        POST,
        PUT,
        DELETE,
        HEAD,
        OPTIONS,
        PATCH,
        TRACE,
        CONNECT
    };

    enum class OpCode : uint8_t {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Reserved1 = 0x3,
        Reserved2 = 0x4,
        Reserved3 = 0x5,
        Reserved4 = 0x6,
        Reserved5 = 0x7,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA,
        Reserved6 = 0xB,
        Reserved7 = 0xC,
        Reserved8 = 0xD,
        Reserved9 = 0xE,
        Reserved10 = 0xF,
    };



    using Headers = std::unordered_map<std::string,std::string>;

    enum class Result {
        Ok = 0,
        NoData = 1,
        ConnectionError = 2,
        AllocationError = 3,
        UTF8Error = 4,
        InvalidOpCode = 5,
        InvalidArgument = 6
    };

    class Message {
    public:
        OpCode opcode;
        std::vector<uint8_t> payload;
        Message();
        Message(const Message &other) noexcept;
        Message(Message &&other);
        Message& operator=(const Message &other);
        Message& operator=(Message &&other) noexcept;
        bool getText(std::string &s);
        bool getRaw(std::vector<uint8_t> &data);
    };

    struct Frame {
        uint8_t fin;
        uint8_t RSV1;
        uint8_t RSV2;
        uint8_t RSV3;
        uint8_t opcode;
        uint64_t payloadLength;
        std::vector<uint8_t> payload;
    };

    void initialize();
    void deinitialize();

    using ErrorCallback = std::function<void(const std::string &message)>;

    class WebSocket;
    using MessageReceivedCallback = std::function<void(const WebSocket *socket, Message &message)>;

    class WebSocket {
    public:
        ErrorCallback onError;
        MessageReceivedCallback onReceived;
        WebSocket();
        WebSocket(AddressFamily addressFamily);
        WebSocket(AddressFamily addressFamily, const std::string &certificatePath, const std::string &privateKeyPath);
        WebSocket(const WebSocket &other);
        WebSocket(WebSocket &&other) noexcept;
        ~WebSocket();
        WebSocket& operator=(const WebSocket &other);
        WebSocket& operator=(WebSocket &&other) noexcept;
        bool bind(const std::string &bindAddress, uint16_t port);
        bool listen(int32_t backlog);
        bool accept(WebSocket &s);
        bool connect(const std::string &uri);
        void close();
        bool setOption(int level, int option, const void *value, uint32_t valueSize);
        void setBlocking(bool isBlocking);
        Result send(OpCode opcode, const void *data, uint64_t size, bool masked);
        Result receive();
        int32_t getFileDescriptor() const { return s.fd; }
        bool isSet() const { return s.fd >= 0; }
    private:
        socket_t s;
        SSL_CTX *sslContext;
        SSL *ssl;
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        bool readAllBytes(void *buffer, size_t size);
        bool writeAllBytes(const void *buffer, size_t size);
        bool drain(size_t size);
        Result writeFrame(OpCode opcode, bool fin, const void *payload, uint64_t payloadSize, bool applyMask);
        Result readFrame(Frame *frame);
        void sendBadRequest(WebSocket &connection);
        bool readHeader(WebSocket &connection, std::string &header);
        bool readMethod(const std::string &header, HttpMethod &method);
        bool readPath(const std::string &header, std::string &path);
        bool readHeaderFields(const std::string &header, Headers &headers);
        bool resolve(const std::string &uri, std::string &ip, uint16_t &port, std::string &hostname);
        IPVersion detectIPVersion(const std::string &ip);
        std::string generateKey();
        std::string generateAcceptKey(const std::string &websocketKey);
        bool verifyKey(const std::string& receivedAcceptKey, const std::string& originalKey);
        bool isValidUTF8(const void *payload, size_t size);
        void writeError(const std::string &message);
    };

    using TimePoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>;

    class Timer {
    public:
        Timer();
        Timer(const Timer &other);
        Timer(Timer &&other) noexcept;
        Timer& operator=(const Timer &other);
        Timer& operator=(Timer &&other) noexcept;
        inline double getDeltaTime() const { return deltaTime; }
        inline double getElapsedTime() const { return elapsedTime; }
        void update();
    private:
        TimePoint tp1;
        TimePoint tp2;
        double deltaTime;
        double elapsedTime;        
    };

    namespace URI {
        bool getScheme(const std::string &uri, std::string &value);
        bool getHost(const std::string &uri, std::string &value);
        bool getPath(const std::string &uri, std::string &value);
        bool getQuery(const std::string &uri, std::string &value);
        bool getFragment(const std::string &uri, std::string &value);
    }

    namespace String {
        bool contains(const std::string &haystack, const std::string &needle);
        bool startsWith(const std::string &haystack, const std::string &needle);
        bool endsWith(const std::string &haystack, const std::string &needle);
        std::string trim(const std::string &s);
        std::string trimStart(const std::string &s);
        std::string trimEnd(const std::string &s);
        std::string toLower(const std::string &s);
        std::string toUpper(const std::string &s);
        std::vector<std::string> split(const std::string &s, const std::string &separator);
        template <typename T>
        bool parseNumber(const std::string& str, T& number) {
            static_assert(std::is_arithmetic<T>::value, "T must be a numeric type");
            std::istringstream iss(str);
            iss >> number;
            return !iss.fail() && iss.eof();
        }
    };
}

#endif