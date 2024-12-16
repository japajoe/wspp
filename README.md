# wspp
A websocket implementation in C++. 

# Note
I am not following the websocket specification (RFC 6455) to the letter but feel free to let me know when you run into any issues.

# Basic Examples
Run as server
```cpp
#include "wspp.h"
#include "signal.h"
#include <thread>
#include <iostream>

using namespace wspp;

bool runApp = true;

void signalHandler(int signum) {
    if(signum == SIGINT)
        runApp = false;
}

int main(int argc, char **argv) {
    signal(SIGINT, &signalHandler);
#ifndef _WIN32
    //Windows does not have this signal (it is fired when a socket is suddenly disconnected).
    //In order to prevent the server from shutting down we intercept this signal and ignore it.
    signal(SIGPIPE, &signalHandler);
#endif

    const uint16_t port = 8080;

    WebSocket socket(AddressFamily::AFInet, WebSocketOption_Reuse | WebSocketOption_NonBlocking);

    if(!socket.bind("0.0.0.0", port))
        return 1;
    
    if(!socket.listen(10)) {
        socket.close();
        return 2;
    }

    std::cout << "Server is listening on port " << port << '\n';

    while(runApp) {
        WebSocket client;

        if(socket.accept(client)) {
            std::string hello = "Hello from server\n";
            client.send(OpCode_Text, hello.c_str(), hello.size(), false);

            Message message;

            if(client.receive(&message)) {
                MessageChunk *chunk = message.chunks;
                std::string msg;

                while(chunk != nullptr) {
                    char *pPayload = (char*)chunk->payload;
                    msg += std::string(pPayload, chunk->payloadLength);
                    chunk = chunk->next;
                }

                message.destroy();

                std::cout << msg << '\n';
            }

            client.close();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    socket.close();

    return 0;
}
```

Run as client
```cpp
#include "wspp.h"
#include "signal.h"
#include <thread>
#include <iostream>

using namespace wspp;

bool runApp = true;

void signalHandler(int signum) {
    if(signum == SIGINT)
        runApp = false;
}

int main(int argc, char **argv) {
    signal(SIGINT, &signalHandler);

    WebSocket socket(AddressFamily::AFInet, WebSocketOption_Reuse);

    if(!socket.connect("wss://pumpportal.fun/api/data")) {
        return 1;
    }

    std::string request = R"({ "method": "subscribeNewToken" })";

    socket.send(OpCode_Text, request.data(), request.size(), true);

    while(runApp) {
        Message message;
        
        if(socket.receive(&message)) {
            MessageChunk *chunk = message.chunks;
            std::string msg;

            while(chunk != nullptr) {
                char *pPayload = (char*)chunk->payload;
                msg += std::string(pPayload, chunk->payloadLength);
                chunk = chunk->next;
            }

            std::cout << msg << "\n\n";

            message.destroy();
        }
    }

    socket.close();

    return 0;
}
```

# Advanced Examples
Run as server
```cpp
#include "wspp/webserver.h"
#include <memory>
#include <signal.h>
#include <iostream>

using namespace wspp;

std::unique_ptr<WebServer> server = nullptr;
bool runApp = true;

void signalHandler(int signum) {
    if(signum == SIGINT) {
        if(server) {
            server->stop();
        }
        runApp = false;
    }
}

void onConnected(uint32_t clientId) {
    std::string text = "A client has connected with ID: " + std::to_string(clientId);
    server->broadcast(PacketType::Text, text.c_str(), text.size());
    std::cout << text << '\n';
}

void onDisconnected(uint32_t clientId) {
    std::string text = "A client has disconnected with ID: " + std::to_string(clientId);
    server->broadcast(PacketType::Text, text.c_str(), text.size());
    std::cout << text << '\n';
}

void onReceivedMessage(uint32_t clientId, Message message) {
    if(message.opcode == OpCode::Text) {
        std::string msg;
        MessageChunk *chunk = message.chunks;

        while(chunk != nullptr) {
            char *payload = (char*)chunk->payload;
            msg += std::string(payload, chunk->payloadLength);
            chunk = chunk->next;
        }

        server->broadcast(PacketType::Text, msg.data(), msg.size());

        std::cout << msg << '\n';
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, &signalHandler);
#ifndef _WIN32
    signal(SIGPIPE, &signalHandler);
#endif

    Configuration configuration;
    configuration.port = 8080;
    configuration.maxClients = 32;
    configuration.bindAddress = "0.0.0.0";

    server = std::make_unique<WebServer>(configuration);
    server->onConnected = onConnected;
    server->onDisconnected = onDisconnected;
    server->onReceived = onReceivedMessage;
    
    if(!server->start())
        return 1;

    while(runApp) {
        server->update();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}
```

Run as client
```cpp
#include <wspp/webclient.h>
#include <memory>
#include <signal.h>
#include <iostream>

std::unique_ptr<WebClient> client = nullptr;
bool runApp = true;

void signalHandler(int signum) {
    if(signum == SIGINT) {
        if(client) {
            client->stop();
        }
        runApp = false;
    }
}

void onConnected() {
    std::cout << "Connected to server\n";
    std::string request = R"({ "method": "subscribeNewToken" })";
    client->send(PacketType::Text, request.c_str(), request.size());
}

void onReceived(Message message) {
    MessageChunk *chunk = message.chunks;
    std::string msg;

    while(chunk != nullptr) {
        char *pPayload = (char*)chunk->payload;
        msg += std::string(pPayload, chunk->payloadLength);
        chunk = chunk->next;
    }

    std::cout << msg << "\n\n";
}

int main(int argc, char **argv) {
    signal(SIGINT, &signalHandler);

    client = std::make_unique<WebClient>("wss://pumpportal.fun/api/data");
    client->onConnected = onConnected;    
    client->onReceived = onReceived;
    
    if(!client->start())
        return 1;

    while(runApp) {
        client->update();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}
```