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

namespace wspp {
    class WebServer;

    enum class DisconnectReason {
        TimeOut,
        ConnectionClosed
    };

    using ServerReceivedCallback = std::function<void(WebServer *server, uint32_t clientId, Message &message)>;
    using ServerConnectedCallback = std::function<void(WebServer *server, uint32_t clientId)>;
    using ServerDisconnectedCallback = std::function<void(WebServer *server, uint32_t clientId, DisconnectReason reason)>;
    using ServerTickCallback = std::function<void(WebServer *server, double deltaTime)>;
    using ServerErrorCallback = std::function<void(WebServer *server, const std::string &message)>;

    struct Configuration {
        uint32_t maxClients;
        uint32_t backlog;
        uint16_t port;
        std::string bindAddress;
        std::string certificatePath;
        std::string privateKeyPath;
    };

    struct Client {
        WebSocket connection;
        uint32_t id;
        uint32_t lastPong;
    };

    class WebServer {
    public:
        ServerReceivedCallback onReceived;
        ServerConnectedCallback onConnected;
        ServerDisconnectedCallback onDisconnected;
        ServerTickCallback onTick;
        ServerErrorCallback onError;
        WebServer();
        ~WebServer();
        bool run(const Configuration &configuration);
        void stop();
        void send(uint32_t clientId, OpCode opcode, const void *data, size_t size);
        void broadcast(OpCode opcode, const void *data, size_t size);
        bool getIP(uint32_t clientId, std::string &ip);
    private:
        WebSocket listener;
        std::vector<Client> clients;
        uint32_t pingTimer;
        Timer timer;
        bool isRunning;
        void acceptConnections();
        void acceptConnection(WebSocket &connection);
        void getMessages();
        void sendPings();
        void sendTo(Client &client, OpCode opcode, const void *data, size_t size);
        void sendAll(OpCode opcode, const void *data, size_t size);
        void onHandleError(const std::string &message);
        void onMessageReceived(const WebSocket *socket, Message &message);
    };
}

#endif