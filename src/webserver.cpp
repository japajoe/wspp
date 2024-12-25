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

#include "webserver.h"
#include <thread>
#include <signal.h>

namespace wspp {
    static std::vector<WebServer*> webServers;
    static bool signalsRegistered = false;

    static void onHandleSignal(int signum) {
        if(signum == SIGINT) {
            for(size_t i = 0; i < webServers.size(); i++)
                webServers[i]->stop();
        }
    }

    static void registerSignals() {
        if(!signalsRegistered) {
            signal(SIGINT, &onHandleSignal);
        #ifndef _WIN32
            signal(SIGPIPE, &onHandleSignal);
        #endif
            signalsRegistered = true;
        }
    }

    WebServer::WebServer() {
        wspp::initialize();
        configuration.bindAddress = "127.0.0.1";
        configuration.port = 8080;
        configuration.maxClients = 32;
        configuration.backlog = 10;
        pingTimer = 0;
        isRunning = false;
        clients.resize(configuration.maxClients);
        webServers.push_back(this);
        registerSignals();
        listener.onError = [this] (const std::string &message) {
            onHandleError(message);
        };
    }

    WebServer::WebServer(const Configuration &configuration) {
        wspp::initialize();
        this->configuration = configuration;
        pingTimer = 0;
        isRunning = false;
        clients.resize(configuration.maxClients);
        webServers.push_back(this);
        registerSignals();
        listener.onError = [this] (const std::string &message) {
            onHandleError(message);
        };
    }

    WebServer::~WebServer() {
        listener.close();

        bool found = false;
        size_t index = 0;
        
        for(size_t i = 0; i < webServers.size(); i++) {
            if(webServers[i] == this) {
                index = i;
                found = true;
                break;
            }
        }

        if(found) {
            webServers.erase(webServers.begin() + index);
        }

        wspp::deinitialize();
    }

    bool WebServer::run() {
        if(isRunning)
            return false;

        if(configuration.certificatePath.size() > 0 && configuration.privateKeyPath.size() > 0)
            listener = WebSocket(AddressFamily::AFInet, configuration.certificatePath, configuration.privateKeyPath);

        if(!listener.bind(configuration.bindAddress, configuration.port))
            return false;

        listener.setBlocking(false);
        
        if(!listener.listen(configuration.backlog))
            return false;

        isRunning = true;

        printf("Server is listening on %s:%zu\n", configuration.bindAddress.c_str(), configuration.port);
        
        while(isRunning) {
            acceptConnections();
            getMessages();
            sendPings();

            timer.update();

            if(onTick)
                onTick(this, timer.getDeltaTime());

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        broadcast(OpCode::Close, nullptr, 0);

        listener.close();

        return true;
    }

    void WebServer::stop() {
        isRunning = false;
    }

    void WebServer::acceptConnections() {
        WebSocket connection;
        
        if(listener.accept(connection)) {
            bool accepted = false;
            for(size_t i = 0; i < clients.size(); i++) {
                Client &client = clients[i];
                
                if(client.connection.isSet())
                    continue;
        
                client.connection = std::move(connection);
                client.connection.setBlocking(false);
                client.lastPong = 0;
                client.id = static_cast<uint32_t>(i);
                client.connection.onReceived = [this] (const WebSocket *socket, Message &message) {
                    onMessageReceived(socket, message);
                };

                if(onConnected)
                    onConnected(this, client.id);

                accepted = true;
                break;
            }
            if(!accepted)
                connection.close();
        }
    }

    void WebServer::getMessages() {
        for (Client &client : clients) {
            if(!client.connection.isSet())
                continue;

            Result result = client.connection.receive();
        }
    }

    void WebServer::sendPings() {
        if(pingTimer >= 30000) {
            sendAll(OpCode::Ping, nullptr, 0);
            pingTimer = 0;
        } else {
            pingTimer += 10;

            for (Client &client : clients) {
                if(!client.connection.isSet())
                    continue;
                
                client.lastPong += 10;

                if(client.lastPong >= 45000) {
                    client.connection.close();
                    client.connection.onReceived = nullptr;
                    if(onDisconnected)
                        onDisconnected(this, client.id, DisconnectReason::TimeOut);
                }
            }
        }
    }

    void WebServer::send(uint32_t clientId, OpCode opcode, const void *data, size_t size) {
        if(clientId >= clients.size())
            return;
        Client &client = clients[clientId];
        sendTo(client, opcode, data, size);
    }

    void WebServer::broadcast(OpCode opcode, const void *data, size_t size) {
        sendAll(opcode, data, size);
    }

    bool WebServer::getIP(uint32_t clientId, std::string &ip) {
        if(clientId >= clients.size())
            return false;
        
        Client &client = clients[clientId];
        
        if(!client.connection.isSet())
            return false;

        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Get the client's address
        if (getpeername(client.connection.getFileDescriptor(), (struct sockaddr*)&client_addr, &client_addr_len) == -1) {
            return false;
        }

        // Convert the IP address to a string
        char ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str)) == nullptr) {
            return false;
        }

        ip = std::string(ip_str);

        return true;
    }

    void WebServer::sendTo(Client &client, OpCode opcode, const void *data, size_t size) {
        if(!client.connection.isSet())
            return;
        client.connection.send(opcode, data, size, false);
    }

    void WebServer::sendAll(OpCode opcode, const void *data, size_t size) {
        for (Client &client : clients) {
            if(!client.connection.isSet())
                continue;
            client.connection.send(opcode, data, size, false);
        }
    }

    void WebServer::onHandleError(const std::string &message) {
        if(onError)
            onError(this, message);
    }

    void WebServer::onMessageReceived(const WebSocket *socket, Message &message) {
        Client *client = nullptr;

        for(size_t i = 0; i < clients.size(); i++) {
            if(clients[i].connection.getFileDescriptor() == socket->getFileDescriptor()) {
                client = &clients[i];
                break;
            }
        }

        if(client == nullptr) {
            return;
        }

        switch(message.opcode) {
            case OpCode::Text:
            case OpCode::Binary:
                if(onReceived)
                    onReceived(this, client->id, message);
                break;
            case OpCode::Close:
                client->connection.close();
                client->connection.onReceived = nullptr;
                if(onDisconnected)
                    onDisconnected(this, client->id, DisconnectReason::ConnectionClosed);
                break;
            case OpCode::Pong:
                client->lastPong = 0;
                break;
            default:
                printf("Received invalid opcode: %zu\n", static_cast<int>(message.opcode));
                break;
        }
    }
}