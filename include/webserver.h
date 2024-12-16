#ifndef WSPP_WEBSERVER_HPP
#define WSPP_WEBSERVER_HPP

#include "wspp.h"
#include <functional>

namespace wspp {
    namespace servers {
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
        wspp::servers::ReceivedCallback onReceived;
        wspp::servers::ConnectedCallback onConnected;
        wspp::servers::DisconnectedCallback onDisconnected;
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
        std::vector<wspp::servers::Client> clients;
        std::thread networkThread;
        std::atomic<bool> runThread;
        ConcurrentQueue<wspp::servers::Packet> incoming;
        ConcurrentQueue<wspp::servers::Packet> outgoing;
        ConcurrentQueue<wspp::servers::Event> events;
        void listen();
        void addConnection(WebSocket &client);
        void receiveMessages();
        void sendMessages();
        void checkForDisconnected(float &pingTimer, float deltaTime);
        void disconnectClient(wspp::servers::Client &client);
    };
}

#endif