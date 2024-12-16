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

namespace wspp {
    WebServer::WebServer() {
        runThread.store(false);
        configuration.bindAddress = "0.0.0.0";
        configuration.port = 8080;
        configuration.maxClients = 32;
        onReceived = nullptr;
        onConnected = nullptr;
        onDisconnected = nullptr;
    }

    WebServer::WebServer(const Configuration &configuration) {
        runThread.store(false);
        this->configuration = configuration;
        onReceived = nullptr;
        onConnected = nullptr;
        onDisconnected = nullptr;
    }

    WebServer::WebServer(const WebServer &other) {
        listener = other.listener;
        runThread = other.runThread.load();
        configuration = other.configuration;
        onReceived = other.onReceived;
        onConnected = other.onConnected;
        onDisconnected = other.onDisconnected;
    }

    WebServer::WebServer(WebServer &&other) noexcept {
        listener = std::move(other.listener);
        runThread = other.runThread.load();    
        other.runThread.store(false);
        configuration = std::move(other.configuration);
        onReceived = std::move(other.onReceived);
        onConnected = std::move(onConnected);
        onDisconnected = std::move(onDisconnected);
    }

    WebServer& WebServer::operator=(const WebServer &other) {
        if(this != &other) {
            listener = other.listener;
            runThread = other.runThread.load();
            configuration = other.configuration;
            onReceived = other.onReceived;
            onConnected = other.onConnected;
            onDisconnected = other.onDisconnected;
        }
        return *this;
    }

    WebServer& WebServer::operator=(WebServer &&other) noexcept {
        if(this != &other) {
            listener = std::move(other.listener);
            runThread = other.runThread.load();
            other.runThread.store(false);
            configuration = std::move(other.configuration);
            onReceived = std::move(other.onReceived);
            onConnected = std::move(onConnected);
            onDisconnected = std::move(onDisconnected);
        }
        return *this;
    }

    void WebServer::start() {
        if (networkThread.joinable() || runThread)
            return;

        runThread.store(true);

        networkThread = std::thread([this]() { listen(); });
    }

    void WebServer::stop() {
        runThread.store(false);

        if (networkThread.joinable())
            networkThread.join();
    }

    void WebServer::update() {
        if(incoming.count() > 0) {
            wspp::wsserver::Packet packet;
            while(incoming.tryDequeue(packet)) {
                if(onReceived)
                    onReceived(packet.clientId, packet.message);
                packet.message.destroy();
            }
        }

        if(events.count() > 0) {
            wspp::wsserver::Event event;
            while(events.tryDequeue(event)) {
                if(event.type == wspp::wsserver::EventType::Connected) {
                    if(onConnected)
                        onConnected(event.clientId);
                } else {
                    if(onDisconnected)
                        onDisconnected(event.clientId);
                }
            }
        }
    }

    void WebServer::listen() {
        clients.resize(configuration.maxClients);
        incoming.drain();
        outgoing.drain();
        events.drain();

        for(size_t i = 0; i < clients.size(); i++) {
            clients[i].id = -1;
        }

        WebSocketOption options = WebSocketOption_Reuse | WebSocketOption_NonBlocking;

        if(configuration.certificatePath.size() > 0 && configuration.privateKeyPath.size() > 0)
            listener = WebSocket(AddressFamily::AFInet, options, configuration.certificatePath, configuration.privateKeyPath);
        else
            listener = WebSocket(AddressFamily::AFInet, options);
        
        if(!listener.bind(configuration.bindAddress, configuration.port)) {
            printf("Failed to bind\n");
            listener.close();
            runThread.store(false);
            return;
        }
        
        if(!listener.listen(10)) {
            printf("Failed to listen\n");
            listener.close();
            runThread.store(false);
            return;
        }

        printf("Server started listening on %s:%zu\n", configuration.bindAddress.c_str(), configuration.port);

        Timer timer;
        float pingTimer = 0.0f;

        while(runThread) {
            WebSocket connection;

            if(listener.accept(connection)) {
                addConnection(connection);
            }

            receiveMessages();
            sendMessages();
            checkForDisconnected(pingTimer, timer.getDeltaTime());
            timer.update();

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        listener.close();
    }

    void WebServer::addConnection(WebSocket &connection) {
        connection.setNonBlocking();

        bool accepted = false;

        for(size_t i = 0; i < clients.size(); i++) {
            if(clients[i].id == -1) {
                clients[i].id = i;
                clients[i].socket = connection;
                clients[i].lastPong = std::chrono::system_clock::now();
                accepted = true;

                wspp::wsserver::Event event;
                event.clientId = i;
                event.type = wspp::wsserver::EventType::Connected;
                events.enqueue(event);

                break;
            }
        }

        if(!accepted)
            connection.close();
    }

    void WebServer::receiveMessages() {
        for(size_t i = 0; i < clients.size(); i++) {
            wspp::wsserver::Client &client = clients[i];

            if(client.id < 0)
                continue;

            Message message;

            if(client.socket.receive(&message)) {
                switch(message.opcode) {
                    case OpCode::Pong: {
                        client.lastPong = std::chrono::system_clock::now();
                        break;
                    }
                    case OpCode::Close: {
                        disconnectClient(client);
                        break;
                    }
                    default: {
                        wspp::wsserver::Packet packet;
                        packet.clientId = client.id;
                        packet.message = message;
                        packet.broadcast = false;
                        incoming.enqueue(packet);
                        break;
                    }
                }
            }
        }
    }

    void WebServer::sendMessages() {
        if(outgoing.count() == 0)
            return;

        wspp::wsserver::Packet packet;

        while(outgoing.tryDequeue(packet)) {
            if(packet.broadcast) {
                for(size_t i = 0; i < clients.size(); i++) {
                    wspp::wsserver::Client &client = clients[i];
                    if(client.id == -1)
                        continue;
                    client.socket.send(packet.message.opcode, packet.message.chunks->payload, packet.message.chunks->payloadLength, false);
                }
            } else {
                if(packet.clientId < clients.size()) {
                    wspp::wsserver::Client &client = clients[packet.clientId];
                    if(client.id >= 0) {
                        client.socket.send(packet.message.opcode, packet.message.chunks->payload, packet.message.chunks->payloadLength, false);
                    }
                }
            }
            
            packet.message.destroy();
        }
    }

    void WebServer::checkForDisconnected(float &pingTimer, float deltaTime) {
        constexpr float pingTime = 5.0f;
        constexpr uint64_t timeOutMilliseconds = 7500;

        if(pingTimer >= pingTime) {
            for(size_t i = 0; i < clients.size(); i++) {
                wspp::wsserver::Client &client = clients[i];
                if(client.id < 0)
                    continue;
                client.socket.send(OpCode::Ping, false);
            }
            pingTimer = 0.0f;
        } else {
            pingTimer += deltaTime;
        }

        auto now = std::chrono::system_clock::now();

        for(size_t i = 0; i < clients.size(); i++) {
            wspp::wsserver::Client &client = clients[i];
            
            if(client.id < 0)
                continue;

            if((now - client.lastPong) > std::chrono::milliseconds(timeOutMilliseconds)) {
                disconnectClient(client);
            }
        }
    }

    void WebServer::send(uint32_t clientId, PacketType type, const void *data, size_t size) {
        if(data == nullptr)
            return;
        
        if(size == 0)
            return;
        
        Message message;
        message.opcode = type == PacketType::Binary ? OpCode::Binary : OpCode::Text;
        message.chunks = new MessageChunk();

        if(message.chunks == nullptr)
            return;

        message.chunks->payload = new uint8_t[size];

        if(message.chunks->payload == nullptr) {
            delete message.chunks;
            return;
        }

        memcpy(message.chunks->payload, data, size);

        message.chunks->payloadLength = size;
        message.chunks->next = nullptr;

        wspp::wsserver::Packet packet;
        packet.clientId = clientId;
        packet.message = message;
        packet.broadcast = false;

        outgoing.enqueue(packet);
    }

    void WebServer::broadcast(PacketType type, const void *data, size_t size) {
        if(data == nullptr)
            return;
        
        if(size == 0)
            return;
        
        Message message;
        message.opcode = type == PacketType::Binary ? OpCode::Binary : OpCode::Text;
        message.chunks = new MessageChunk();

        if(message.chunks == nullptr)
            return;

        message.chunks->payload = new uint8_t[size];

        if(message.chunks->payload == nullptr) {
            delete message.chunks;
            return;
        }

        memcpy(message.chunks->payload, data, size);

        message.chunks->payloadLength = size;
        message.chunks->next = nullptr;

        wspp::wsserver::Packet packet;
        packet.clientId = 0;
        packet.message = message;
        packet.broadcast = true;

        outgoing.enqueue(packet);
    }

    void WebServer::disconnectClient(wspp::wsserver::Client &client) {
        wspp::wsserver::Event event;
        event.clientId = client.id;
        event.type = wspp::wsserver::EventType::Disconnected;

        client.socket.close();
        client.id = -1;

        events.enqueue(event);
    }
}