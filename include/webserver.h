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

#ifndef WSPP_WEBSERVER_HPP
#define WSPP_WEBSERVER_HPP

#include "wspp.h"
#include <functional>

namespace wspp {
    namespace wsserver {
        using TimeStamp = std::chrono::_V2::system_clock::time_point;

        struct Client {
            WebSocket socket;
            int32_t id;
            TimeStamp lastPong;
        };

        struct Packet {
            uint32_t clientId;
            Message message;
            bool broadcast;
        };

        enum class EventType {
            Connected,
            Disconnected
        };

        struct Event {
            EventType type;
            uint32_t clientId;
        };

        using ReceivedCallback = std::function<void(uint32_t clientId, Message message)>;
        using ConnectedCallback = std::function<void(uint32_t clientId)>;
        using DisconnectedCallback = std::function<void(uint32_t clientId)>;
    }

    struct Configuration {
        std::string bindAddress;
        std::string certificatePath;
        std::string privateKeyPath;
        uint16_t port;
        uint32_t maxClients;
    };

    class WebServer {
    public:
        wspp::wsserver::ReceivedCallback onReceived;
        wspp::wsserver::ConnectedCallback onConnected;
        wspp::wsserver::DisconnectedCallback onDisconnected;
        WebServer();
        WebServer(const Configuration &configuration);
        WebServer(const WebServer &other);
        WebServer(WebServer &&other) noexcept;
        WebServer& operator=(const WebServer &other);
        WebServer& operator=(WebServer &&other) noexcept;
        void start();
        void stop();
        void update();
        void send(uint32_t clientId, PacketType type, const void *data, size_t size);
        void broadcast(PacketType type, const void *data, size_t size);
    private:
        Configuration configuration;
        WebSocket listener;
        std::vector<wspp::wsserver::Client> clients;
        std::thread networkThread;
        std::atomic<bool> runThread;
        ConcurrentQueue<wspp::wsserver::Packet> incoming;
        ConcurrentQueue<wspp::wsserver::Packet> outgoing;
        ConcurrentQueue<wspp::wsserver::Event> events;
        void listen();
        void addConnection(WebSocket &client);
        void receiveMessages();
        void sendMessages();
        void checkForDisconnected(float &pingTimer, float deltaTime);
        void disconnectClient(wspp::wsserver::Client &client);
    };
}

#endif