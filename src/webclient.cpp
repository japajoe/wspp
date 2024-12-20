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

#include "webclient.h"
#include <thread>
#include <signal.h>

namespace wspp {
    static std::vector<WebClient*> webClients;
    static bool signalsRegistered = false;

    static void onHandleSignal(int signum) {
        if(signum == SIGINT) {
            for(size_t i = 0; i < webClients.size(); i++)
                webClients[i]->stop();
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

    WebClient::WebClient() {
        wspp::initialize();
        isRunning = false;
        webClients.push_back(this);
        registerSignals();
    }

    WebClient::WebClient(const std::string &uri) {
        wspp::initialize();
        this->uri = uri;
        isRunning = false;
        webClients.push_back(this);
        registerSignals();
    }

    WebClient::~WebClient() {
        connection.close();
        
        bool found = false;
        size_t index = 0;
        
        for(size_t i = 0; i < webClients.size(); i++) {
            if(webClients[i] == this) {
                index = i;
                found = true;
                break;
            }
        }

        if(found) {
            webClients.erase(webClients.begin() + index);
        }

        wspp::deinitialize();
    }

    bool WebClient::run() {
        if(isRunning)
            return false;

        if(uri.size() == 0) {
            printf("URI is not set\n");
            return false;
        }

        if(!connection.connect(uri))
            return false;

        isRunning = true;
        
        connection.setBlocking(false);
        
        if(onConnected)
            onConnected(this);

        while(isRunning) {
            getMessages();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        connection.close();

        return true;
    }

    void WebClient::stop() {
        isRunning = false;    
    }

    void WebClient::getMessages() {
        if(!connection.isSet())
            return;

        Message message;

        Result result = connection.receive(&message);

        if(result == Result::Ok) {
            switch(message.opcode) {
                case OpCode::Text:
                case OpCode::Binary:
                    if(onReceived)
                        onReceived(this, message);
                    break;
                case OpCode::Close:
                    connection.close();
                    if(onDisconnected)
                        onDisconnected(this);
                    break;
                default:
                    break;
            }
        }
        
        message.destroy();
    }

    void WebClient::send(OpCode opcode, const void *data, size_t size) {
        if(!connection.isSet())
            return;
        connection.send(opcode, data, size, true);
    }
}