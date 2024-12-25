# wspp
A websocket implementation in C++. 

# Note
In general I'm following the `it works for me™` guidelines and I am not following the websocket specification (RFC 6455) to the letter, although feel free to let me know when you run into any issues.

# Dependencies
- [OpenSSL](https://github.com/openssl/openssl)

# Client Example
```cpp
#include <wspp/webclient.h>
#include <iostream>

using namespace wspp;

void onConnected(WebClient *client);
void onDisconnected(WebClient *client);
void onReceived(WebClient *client, Message &message);
void onTick(WebClient *client, double deltaTime);
void onError(WebClient *client, const std::string &message);

int main(int argc, char **argv) {
    WebClient client;
    client.onConnected = &onConnected;
    client.onDisconnected = &onDisconnected;
    client.onReceived = &onReceived;
    client.onTick = &onTick;
    client.onError = &onError;
    client.run("wss://pumpportal.fun/api/data");
    
    return 0;
}

void onConnected(WebClient *client) {
    std::cout << "Connected to server\n";
    std::string request = R"({ "method": "subscribeNewToken" })";
    client->send(OpCode::Text, request.c_str(), request.size());
}

void onDisconnected(WebClient *client) {
    std::cout << "Disconnected from server\n";
}

void onReceived(WebClient *client, Message &message) {
    if(message.opcode == OpCode::Text) {
        std::string msg;
        if(message.getText(msg)) {
            std::cout << msg << "\n\n";
        }
    }
}

void onTick(WebClient *client, double deltaTime) {

}

void onError(WebClient *client, const std::string &message) {
    std::cout << message << '\n';
}
```
# Server Example
```cpp
#include <wspp/webserver.h>
#include <iostream>

using namespace wspp;

void onConnected(WebServer *server, uint32_t clientId);
void onDisconnected(WebServer *server, uint32_t clientId, DisconnectReason reason);
void onReceived(WebServer *server, uint32_t clientId, Message &message);
void onTick(WebServer *server, double deltaTime);
void onError(WebServer *server, const std::string &message);

int main(int argc, char **argv) {
    Configuration configuration;
    configuration.backlog = 10;
    configuration.bindAddress = "127.0.0.1";
    configuration.maxClients = 32;
    configuration.port = 8080;

    WebServer server;
    server.onConnected = &onConnected;
    server.onDisconnected = &onDisconnected;
    server.onReceived = &onReceived;
    server.onTick = &onTick;
    server.onError = &onError;
    server.run(configuration);
    
    return 0;
}

void onConnected(WebServer *server, uint32_t clientId) {
    std::cout << "A client has connected with ID: " << clientId << '\n';
}

void onDisconnected(WebServer *server, uint32_t clientId, DisconnectReason reason) {
    if(reason == DisconnectReason::TimeOut)
        std::cout << "A client has disconnected (timeout) with ID: " << clientId << '\n';
    else
        std::cout << "A client has disconnected (closed) with ID: " << clientId << '\n';
}

void onReceived(WebServer *server, uint32_t clientId, Message &message) {
    if(message.opcode == OpCode::Text) {
        std::string msg;

        if(message.getText(msg)) {
            std::cout << msg << '\n';
            server->broadcast(OpCode::Text, msg.data(), msg.size());
        }
    }
}

void onTick(WebServer *server, double deltaTime) {

}

void onError(WebServer *server, const std::string &message) {
    std::cout << message << '\n';
}
```