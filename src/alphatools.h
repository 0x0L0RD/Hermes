#include <Windows.h>
#include <WinUser.h>
#include <bcrypt.h>

#define CMD_SIZE 256
#define KEY_SIZE 64
#define RESPONSE_SIZE 4096
#define DEFAULT_BUFFER_SIZE 1024

VOID AlphaCrypt(PCHAR Key, PCHAR buffer, INT lengthOfBuffer);
VOID Error(LPCWSTR error, LPCWSTR type);
PCHAR GenerateKey();

VOID AlphaCrypt(PCHAR Key, PCHAR buffer, INT lengthOfBuffer) {
    INT lengthOfKey = strlen(Key);
    for (INT iterator = 0; iterator < lengthOfBuffer-1; iterator++) {
        buffer[iterator] = buffer[iterator] ^ Key[iterator % (lengthOfKey - 1)];
    }

}

PCHAR GenerateKey() {
    INT Number;
    NTSTATUS result;
    PCHAR key = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KEY_SIZE);
    
    BCRYPT_ALG_HANDLE CryptAlgo;
    BCryptOpenAlgorithmProvider(&CryptAlgo, BCRYPT_RNG_ALGORITHM, NULL, 0);


    for (int i = 0; i < KEY_SIZE-1; i++) {
        BCryptGenRandom(CryptAlgo, (PUCHAR)&Number, sizeof(INT), 0);
        key[i] = ((Number % 0x7E)+1);
    }

    BCryptCloseAlgorithmProvider(CryptAlgo, 0);
    key[KEY_SIZE-1] = 0x0;

    return key;
}

VOID Error( LPCWSTR error, LPCWSTR type ){
    MessageBox(NULL, error, type, MB_ICONEXCLAMATION | IDOK);
    ExitProcess(1);
}
