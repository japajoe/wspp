#include "wspp.h"
#include "signal.h"
using namespace wspp;

bool runApp = true;

void signalHandler(int signum) {
    if(signum == SIGINT)
        runApp = false;
}

int main(int argc, char **argv) {
    signal(SIGINT, &signalHandler);

    WebSocket socket;

    if(!socket.connect("wss://pumpportal.fun/api/data"))
        return 1;

    std::string request = R"({ "method": "subscribeNewToken" })";

    socket.send(OpCode::OpCode_Text, request.data(), request.size());

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

    printf("Closing\n");

    socket.close();

    return 0;
}