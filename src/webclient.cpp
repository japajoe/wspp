#include "webclient.h"

namespace wspp {
    WebClient::WebClient() {
        runThread.store(false);
        uri = "ws://localhost:8080";
        onReceived = nullptr;
        onConnected = nullptr;
        onDisconnected = nullptr;
    }

    WebClient::WebClient(const std::string &uri) {
        runThread.store(false);
        this->uri = uri;
        onReceived = nullptr;
        onConnected = nullptr;
        onDisconnected = nullptr;
    }

    WebClient::WebClient(const WebClient &other) {
        socket = other.socket;
        runThread = other.runThread.load();
        uri = other.uri;
        onReceived = other.onReceived;
        onConnected = other.onConnected;
        onDisconnected = other.onDisconnected;
    }

    WebClient::WebClient(WebClient &&other) noexcept {
        socket = std::move(other.socket);
        runThread = other.runThread.load();    
        other.runThread.store(false);
        uri = std::move(other.uri);
        onReceived = std::move(other.onReceived);
        onConnected = std::move(onConnected);
        onDisconnected = std::move(onDisconnected);
    }

    WebClient& WebClient::operator=(const WebClient &other) {
        if(this != &other) {
            socket = other.socket;
            runThread = other.runThread.load();
            uri = other.uri;
            onReceived = other.onReceived;
            onConnected = other.onConnected;
            onDisconnected = other.onDisconnected;
        }
        return *this;
    }

    WebClient& WebClient::operator=(WebClient &&other) noexcept {
        if(this != &other) {
            socket = std::move(other.socket);
            runThread = other.runThread.load();
            other.runThread.store(false);
            uri = std::move(other.uri);
            onReceived = std::move(other.onReceived);
            onConnected = std::move(onConnected);
            onDisconnected = std::move(onDisconnected);
        }
        return *this;
    }

    void WebClient::start() {
        if (networkThread.joinable() || runThread)
            return;

        runThread.store(true);

        networkThread = std::thread([this]() { connect(); });
    }

    void WebClient::stop() {
        runThread.store(false);

        if (networkThread.joinable())
            networkThread.join();
    }

    void WebClient::update() {
        if(incoming.count() > 0) {
            Message message;
            while(incoming.tryDequeue(message)) {
                if(onReceived)
                    onReceived(message);
                message.destroy();
            }
        }

        if(events.count() > 0) {
            wspp::clients::EventType event;
            while(events.tryDequeue(event)) {
                if(event == wspp::clients::EventType::Connected) {
                    if(onConnected)
                        onConnected();
                } else {
                    if(onDisconnected)
                        onDisconnected();
                }
            }
        }
    }

    void WebClient::connect() {
        incoming.drain();
        outgoing.drain();
        events.drain();

        socket = WebSocket(AddressFamily::AFInet, WebSocketOption_None);
        
        if(!socket.connect(uri)) {
            printf("Failed to connect\n");
            socket.close();
            runThread.store(false);
            return;
        }

        socket.setNonBlocking();

        wspp::clients::EventType connectedEvent = wspp::clients::EventType::Connected;
        events.enqueue(connectedEvent);

        while(runThread) {
            receiveMessages();
            sendMessages();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        socket.close();
    }

    void WebClient::receiveMessages() {
        Message message;

        if(socket.receive(&message)) {
            incoming.enqueue(message);
        }
    }

    void WebClient::sendMessages() {
        if(outgoing.count() == 0) {
            return;
        }

        Message message;

        while(outgoing.tryDequeue(message)) {
            socket.send(message.opcode, message.chunks->payload, message.chunks->payloadLength, true);
            message.destroy();
        }
    }

    void WebClient::send(PacketType type, const void *data, size_t size) {
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

        outgoing.enqueue(message);
    }
}