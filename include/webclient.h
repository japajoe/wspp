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

#ifndef WSPP_WEBCLIENT_HPP
#define WSPP_WEBCLIENT_HPP

#include "wspp.h"
#include <functional>

namespace wspp {
    namespace wsclient {
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
        wspp::wsclient::ReceivedCallback onReceived;
        wspp::wsclient::ConnectedCallback onConnected;
        wspp::wsclient::DisconnectedCallback onDisconnected;
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
        ConcurrentQueue<wspp::wsclient::EventType> events;
        void connect();
        void receiveMessages();
        void sendMessages();
    };
}

#endif