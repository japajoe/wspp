# wspp
A websocket implementation in C++. 

# Note
I am not following the websocket specification (RFC 6455) to the letter but I think this library covers the basics for now.

# Examples
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

    printf("Server is listening on port %zu\n", port);

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
#ifndef _WIN32
    //Windows does not have this signal (it is fired when a socket is suddenly disconnected).
    signal(SIGPIPE, &signalHandler);
#endif

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