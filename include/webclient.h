#ifndef WSPP_WEBCLIENT_HPP
#define WSPP_WEBCLIENT_HPP

#include "wspp.h"
#include <functional>

namespace wspp {
    namespace clients {
        enum class EventType {
            Connected,
            Disconnected
        };

        using ReceivedCallback = std::function<void(Message message)>;
        using ConnectedCallback = std::function<void()>;
        using DisconnectedCallback = std::function<void()>;
    }

    class WebClient {
    public:
        wspp::clients::ReceivedCallback onReceived;
        wspp::clients::ConnectedCallback onConnected;
        wspp::clients::DisconnectedCallback onDisconnected;
        WebClient();
        WebClient(const std::string &uri);
        WebClient(const WebClient &other);
        WebClient(WebClient &&other) noexcept;
        WebClient& operator=(const WebClient &other);
        WebClient& operator=(WebClient &&other) noexcept;
        void start();
        void stop();
        void update();
        void send(PacketType type, const void *data, size_t size);
    private:
        std::string uri;
        WebSocket socket;
        std::thread networkThread;
        std::atomic<bool> runThread;
        ConcurrentQueue<Message> incoming;
        ConcurrentQueue<Message> outgoing;
        ConcurrentQueue<wspp::clients::EventType> events;
        void connect();
        void receiveMessages();
        void sendMessages();
    };
}

#endif