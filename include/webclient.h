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
#include <vector>
#include <functional>

namespace wspp {
    class WebClient;

    using ClientReceivedCallback = std::function<void(WebClient *client, Message &message)>;
    using ClientConnectedCallback = std::function<void(WebClient *client)>;
    using ClientDisconnectedCallback = std::function<void(WebClient *client)>;
    using ClientTickCallback = std::function<void(WebClient *client)>;

    class WebClient {
    public:
        ClientReceivedCallback onReceived;
        ClientConnectedCallback onConnected;
        ClientDisconnectedCallback onDisconnected;
        ClientTickCallback onTick;
        ErrorCallback onError;
        WebClient();
        WebClient(const std::string &uri);
        ~WebClient();
        bool run();
        void stop();
        void send(OpCode opcode, const void *data, size_t size);
    private:
        WebSocket connection;
        std::string uri;
        bool isRunning;
        void getMessages();
        void onHandleError(const std::string &message);
        void onMessageReceived(const WebSocket *socket, Message message);
    };
}

#endif