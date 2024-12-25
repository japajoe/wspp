# wspp
A websocket implementation in C++. 

# Note
I am not following the websocket specification (RFC 6455) to the letter but feel free to let me know when you run into any issues.

# Client Example
```cpp
#include <wspp/webclient.h>

using namespace wspp;

void onConnected(WebClient *client);
void onDisconnected(WebClient *client);
void onReceived(WebClient *client, Message &message);

int main(int argc, char **argv) {
    WebClient client("wss://pumpportal.fun/api/data");
    client.onConnected = &onConnected;
    client.onDisconnected = &onDisconnected;
    client.onReceived = &onReceived;
    client.run();
    return 0;
}

void onConnected(WebClient *client) {
    printf("Connected to server\n");
    std::string request = R"({ "method": "subscribeNewToken" })";
    client->send(OpCode::Text, request.data(), request.size());
}

void onDisconnected(WebClient *client) {
    printf("Disconnected from server\n");
}

void onReceived(WebClient *client, Message &message) {
    if(message.opcode == OpCode::Text) {
        std::string msg;
        if(message.getText(msg)) {
            printf("%s\n\n", msg.c_str());
        }
    }
}
```
# Server Example
```cpp
#include <wspp/webserver.h>

using namespace wspp;

void onConnected(WebServer *server, uint32_t clientId);
void onDisconnected(WebServer *server, uint32_t clientId, DisconnectReason reason);
void onReceived(WebServer *server, uint32_t clientId, Message &message);

int main(int argc, char **argv) {
    Configuration configuration;
    configuration.backlog = 10;
    configuration.bindAddress = "127.0.0.1";
    configuration.maxClients = 32;
    configuration.port = 8080;

    WebServer server(configuration);
    server.onConnected = &onConnected;
    server.onDisconnected = &onDisconnected;
    server.onReceived = &onReceived;
    server.run();
    
    return 0;
}

void onConnected(WebServer *server, uint32_t clientId) {
    printf("A client has connected with ID: %zu\n", clientId);
}

void onDisconnected(WebServer *server, uint32_t clientId, DisconnectReason reason) {
    printf("A client has disconnected with ID: %zu\n", clientId);
}

void onReceived(WebServer *server, uint32_t clientId, Message &message) {
    if(message.opcode == OpCode::Text) {
        std::string msg;

        if(message.getText(msg)) {
            printf("%s\n", msg.c_str());
            server->broadcast(OpCode::Text, msg.data(), msg.size());
        }
    }
}
```