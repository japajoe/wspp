#include "wspp.h"
#include "signal.h"
#include <thread>
using namespace wspp;

bool runApp = true;

void signalHandler(int signum) {
    if(signum == SIGINT)
        runApp = false;
}

int runAsServer();
int runAsClient();

int main(int argc, char **argv) {
    signal(SIGINT, &signalHandler);

    //return runAsServer();
    return runAsClient();
}

int runAsServer() {
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
            client.send(OpCode::OpCode_Text, hello.c_str(), hello.size(), true);

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

                printf("%s\n", msg.c_str());
            }

        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    socket.close();

    return 0;
}

int runAsClient() {
    WebSocket socket(AddressFamily::AFInet, WebSocketOption_Reuse);

    if(!socket.connect("wss://pumpportal.fun/api/data")) {
        return 1;
    }

    std::string request = R"({ "method": "subscribeNewToken" })";

    socket.send(OpCode::OpCode_Text, request.data(), request.size(), true);

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

            printf("%s\n\n", msg.c_str());

            message.destroy();
        }
    }

    socket.close();

    return 0;
}