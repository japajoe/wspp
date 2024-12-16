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
#include <exception>
#include <unordered_map>
#include <sstream>
#include <atomic>
#include <thread>
#include <chrono>

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
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <openssl/ssl.h>

namespace wspp {
    typedef struct sockaddr_in sockaddr_in_t;
    typedef struct sockaddr_in6 sockaddr_in6_t;

    typedef union {
        sockaddr_in_t ipv4;
        sockaddr_in6_t ipv6;
    } socket_address_t;

    typedef struct {
        int32_t fd;
        socket_address_t address;
    } socket_t;

    enum class AddressFamily : int {
        AFInet = AF_INET,
        AFInet6 = AF_INET6
    };

    enum class IPVersion {
        IPv4,
        IPv6,
        Invalid
    };

    class Socket {
    public:
        Socket();
        Socket(AddressFamily addressFamily);
        Socket(const Socket &other);
        Socket(Socket &&other) noexcept;
        Socket& operator=(const Socket &other);
        Socket& operator=(Socket &&other) noexcept;
        void close();
        bool bind(const std::string &address, uint16_t port);
        bool connect(const std::string &ip, uint16_t port);
        bool listen(int32_t backlog);
        bool accept(Socket &socket);
        bool setOption(int level, int option, const void *value, uint32_t valueSize);
        void setNonBlocking();
        int32_t readByte();
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        ssize_t receiveFrom(void *buffer, size_t size);
        ssize_t sendTo(const void *buffer, size_t size);
        int32_t getFileDescriptor() const;
        bool isSet() const;
        static IPVersion detectIPVersion(const std::string &ip);
    private:
        socket_t s;
    };

    class SslException : public std::exception {
    public:
        SslException(const char* message) : message_(message) {}

        const char *what() const noexcept override {
            return message_.c_str();
        }
    private:
        std::string message_;
    };

    class SslContext {
    public:
        SslContext();
        SslContext(const SslContext &other);
        SslContext(SslContext &&other) noexcept;
        SslContext& operator=(const SslContext &other);
        SslContext& operator=(SslContext &&other) noexcept;
        void dispose();
        SSL_CTX *getContext() const;
        bool isServerContext() const;
        bool initialize(const char *certificatePath, const char *privateKeyPath);
    private:
        SSL_CTX *context;
    };

    class SslStream {
    public:
        SslStream();
        //Used to create an SslStream for incoming connections
        SslStream(Socket socket, SslContext sslContext);
        //Used to create an SslStream for outgoing connections
        SslStream(Socket socket, SslContext sslContext, const char *hostName);
        SslStream(const SslStream &other);
        SslStream(SslStream &&other) noexcept;
        SslStream& operator=(const SslStream &other);
        SslStream& operator=(SslStream &&other) noexcept;
        int32_t readByte();
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        void close();
        bool isSet() const;
    private:
        SSL *ssl;
    };

    class NetworkStream {
    public:
        NetworkStream();
        NetworkStream(Socket socket);
        NetworkStream(Socket socket, SslStream ssl);
        NetworkStream(const NetworkStream &other);
        NetworkStream(NetworkStream &&other) noexcept;
        NetworkStream& operator=(const NetworkStream &other);
        NetworkStream& operator=(NetworkStream &&other) noexcept;
        int32_t readByte();
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        void close();
        bool isSecure() const;
    private:
        Socket socket;
        SslStream ssl;
    };

    enum class PacketType {
        Binary,
        Text
    };

    enum class OpCode : uint8_t {
        Control = 0x0,
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

    struct Frame {
        uint8_t fin;
        uint8_t RSV1;
        uint8_t RSV2;
        uint8_t RSV3;
        uint8_t opcode;
        uint8_t maskingKey[4];  //Only present if the client is sending data (server-to-client frames don’t have a mask).
        uint64_t payloadLength; //Payload length: 1 byte for lengths 0-125, 2 bytes for lengths up to 65535, and 8 bytes for very large messages.
        uint8_t *payload;       //Payload data: The actual data, which may need to be unmasked.
    };

    struct MessageChunk {
        MessageChunk *next;
        uint64_t payloadLength;
        uint8_t *payload;
    };

    class Message {
    public:
        OpCode opcode;
        MessageChunk *chunks;
        Message();
        Message(const Message &other) noexcept;
        Message(Message &&other);
        Message& operator=(const Message &other);
        Message& operator=(Message &&other) noexcept;
        void destroy();
    };

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

    using Headers = std::unordered_map<std::string,std::string>;

    enum WebSocketOption_ {
        WebSocketOption_None = 0,
        WebSocketOption_Reuse = 1 << 0,
        WebSocketOption_NonBlocking = 1 << 1,
    };

    typedef int WebSocketOption;

    class WebSocket {
    public:
        WebSocket();
        WebSocket(AddressFamily addressFamily, WebSocketOption options);
        WebSocket(AddressFamily addressFamily, WebSocketOption options, const std::string &certificatePath, const std::string &privateKeyPath);
        WebSocket(const WebSocket &other);
        WebSocket(WebSocket &&other) noexcept;
        WebSocket& operator=(const WebSocket &other);
        WebSocket& operator=(WebSocket &&other) noexcept;
        void close();
        bool bind(const std::string &address, uint16_t port);
        bool connect(const std::string &url);
        bool listen(int32_t backlog);
        bool accept(WebSocket &socket);
        bool setOption(int level, int option, const void *value, uint32_t valueSize);
        void setNonBlocking();
        bool send(OpCode opcode, bool masked);
        bool send(OpCode opcode, const void *data, size_t size, bool masked);
        bool receive(Message *message);
    private:
        Socket socket;
        SslContext sslContext;
        SslStream sslStream;
        NetworkStream stream;
        ssize_t read(void *buffer, size_t size);
        ssize_t write(const void *buffer, size_t size);
        ssize_t peek(void *buffer, size_t size);
        bool readHeader(WebSocket &connection, std::string &header);
        HttpMethod readMethod(const std::string &header);
        std::string readPath(const std::string &header);
        Headers readHeaderFields(const std::string &header);
        void sendBadRequest(WebSocket webSocket);
        bool writeFrame(OpCode opcode, bool fin, const void *payload, uint64_t payloadSize, bool applyMask);
        bool readFrame(Frame *frame);
        bool isValidUTF8(const void *payload, size_t size);
        std::string generateKey();
        std::string generateAcceptKey(const std::string &websocketKey);
        bool verifyKey(const std::string& receivedAcceptKey, const std::string& originalKey);
        bool resolve(const std::string &uri, std::string &ip, uint16_t &port, std::string &hostname);
    };

    class URI {
    public:
        URI(const std::string &uriString);
        bool getScheme(std::string &value);
        bool getHost(std::string &value);
        bool getPath(std::string &value);
        bool getQuery(std::string &value);
        bool getFragment(std::string &value);
    private:
        std::string uri;
    };

    struct HostInfo {
        std::string name;
        std::string ip;
        uint16_t port;
    };

    class String {
    public:
        static bool contains(const std::string &haystack, const std::string &needle);
        static bool startsWith(const std::string &haystack, const std::string &needle);
        static bool endsWith(const std::string &haystack, const std::string &needle);
        static std::string trim(const std::string &s);
        static std::string trimStart(const std::string &s);
        static std::string trimEnd(const std::string &s);
        static std::string toLower(const std::string &s);
        static std::string toUpper(const std::string &s);
        static std::vector<std::string> split(const std::string &s, const std::string &separator);
        template <typename T>
        static bool parseNumber(const std::string& str, T& number) {
            static_assert(std::is_arithmetic<T>::value, "T must be a numeric type");
            std::istringstream iss(str);
            iss >> number;
            return !iss.fail() && iss.eof();
        }
    };

    template <typename T>
    class ConcurrentQueue {
    public:
        ConcurrentQueue() {
            _consumerCursor = 0;
            _producerCursor = 0;
            size_t capacity = 1024;
            capacity = nextPowerOfTwo(capacity);
            _modMask = capacity - 1;
            _entries.resize(capacity);
        }

        ConcurrentQueue(size_t capacity) {
            _consumerCursor = 0;
            _producerCursor = 0;
            capacity = nextPowerOfTwo(capacity);
            _modMask = capacity - 1;
            _entries.resize(capacity);
        }

        ConcurrentQueue(const ConcurrentQueue &other) {
            _entries = other._entries;
            _modMask = other._modMask;
            _consumerCursor = other._consumerCursor;
            _producerCursor = other._producerCursor;
        }

        ConcurrentQueue(ConcurrentQueue &&other) noexcept {
            _entries = std::move(other._entries);
            _modMask = other._modMask;
            _consumerCursor = other._consumerCursor;
            _producerCursor = other._producerCursor;
        }

        ConcurrentQueue& operator=(const ConcurrentQueue &other) {
            if(this != &other) {
                _entries = other._entries;
                _modMask = other._modMask;
                _consumerCursor = other._consumerCursor;
                _producerCursor = other._producerCursor;
            }
            return *this;
        }

        ConcurrentQueue& operator=(ConcurrentQueue &&other) noexcept {
            if(this != &other) {
                _entries = std::move(other._entries);
                _modMask = other._modMask;
                _consumerCursor = other._consumerCursor;
                _producerCursor = other._producerCursor;
            }
            return *this;
        }

        // Add an item to the end of the container
        void enqueue(const T &item) {
            auto next = _producerCursor.fetch_add(1, std::memory_order_acq_rel) + 1;

            // Wait for space to be available
            long wrapPoint = next - _entries.size();
            long min = _consumerCursor.load(std::memory_order_acquire);
            while (wrapPoint > min) {
                min = _consumerCursor.load(std::memory_order_acquire);
                std::this_thread::yield();
            }

            // Add item to the container
            _entries[next & _modMask] = item;

            // Update producer cursor
            _producerCursor.store(next, std::memory_order_release);
        }

        // Remove an item from the beginning of the container
        T dequeue() {
            auto next = _consumerCursor.fetch_add(1, std::memory_order_acq_rel) + 1;

            // Wait for data to be available
            while (_producerCursor.load(std::memory_order_acquire) < next) {
                std::this_thread::yield();
            }

            // Get item from the container
            auto result = _entries[next & _modMask];

            // Update consumer cursor
            _consumerCursor.store(next, std::memory_order_release);

            return result;
        }

        // Try to remove an item from the beginning of the container
        bool tryDequeue(T &obj) {
            auto next = _consumerCursor.load(std::memory_order_acquire) + 1;

            // Check if data is available
            if (_producerCursor.load(std::memory_order_acquire) < next) {
                return false;
            }

            // Get item from the container
            obj = dequeue();

            return true;
        }

        // Get the number of items in the container
        int count() const {
            return static_cast<int>(_producerCursor.load(std::memory_order_acquire) -
                                    _consumerCursor.load(std::memory_order_acquire));
        }

        void drain() {
            T val;
            while (tryDequeue(val)) {}
        }

    private:
        std::vector<T> _entries;
        size_t _modMask;
        std::atomic_size_t _consumerCursor;// = 0;
        std::atomic_size_t _producerCursor;// = 0;

        // Compute the next power of two
        static size_t nextPowerOfTwo(size_t n) {
            size_t result = 2;
            while (result < n) {
                result <<= 1;
            }
            return result;
        }
    };

    using TimePoint = std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds>;

    class Timer {
    public:
        Timer();
        Timer(const Timer &other);
        Timer(Timer &&other) noexcept;
        Timer& operator=(const Timer &other);
        Timer& operator=(Timer &&other) noexcept;
        inline float getDeltaTime() const { return deltaTime; }
        void update();
    private:
        TimePoint tp1;
        TimePoint tp2;
        float deltaTime;
        float elapsedTime;        
    };
}

#endif