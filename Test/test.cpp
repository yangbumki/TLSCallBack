#include <Windows.h>
#include <cstdio>

#define IMAGE_TLS_MAIN		FALSE
#define MAIN				TRUE

#if IMAGE_TLS_MAIN
typedef IMAGE_TLS_DIRECTORY64 ITD;


/* D:\Source\TLSCallBack\Test\x64\Release\Test.exe (2024-03-19 오후 4:58:18)
   StartOffset(h): 00001900, EndOffset(h): 0000193F, 길이(h): 00000040 */

unsigned char rawData[64] = {
	0xF8, 0x28, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xF9, 0x28, 0x00, 0x40,
	0x01, 0x00, 0x00, 0x00, 0x40, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
	0x40, 0x22, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x10, 0x00, 0x18, 0x00, 0x00, 0x00, 0x02, 0x80, 0x02, 0x80,
	0x40, 0x25, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x6C, 0x25, 0x00, 0x00,
	0x18, 0x00, 0x00, 0x00
};


int main() {
	ITD itd = { 0, };
	SIZE_T itdSize = 0, rawDataSize = 0;

	itdSize = sizeof(ITD);
	rawDataSize = sizeof(rawData);

	if (rawDataSize <= itdSize) {
		printf_s("Plz RawData is so small \n");
		return 0;
	}

	memcpy(&itd, rawData, itdSize);

	printf_s("StartAddressOfRawData: %p \n", itd.StartAddressOfRawData);
	printf_s("EndAddressOfRawData: %p \n", itd.EndAddressOfRawData);
	printf_s("AddressOfIndex: %p \n", itd.AddressOfIndex);
	printf_s("AddressOfCallBacks: %p \n", itd.AddressOfCallBacks);
	printf_s("SizeOfZeroFill: %x \n", itd.SizeOfZeroFill);
	printf_s("UNION: %x \n", itd.Characteristics);

	return 0;
};

#endif


#if MAIN

#define X86		FALSE
#define BUFSIZE				1024

void NTAPI TLS_CALLBACK1(PVOID tlsHandle, DWORD tlsReason, PVOID tlsReserved);
void NTAPI TLS_CALLBACK2(PVOID tlsHandle, DWORD tlsReason, PVOID tlsReserved);

#if X86
#pragma comment(linker, "/INCLUDE:__tls_used") // x86 버전
#else
#pragma comment(linker, "/INCLUDE:_tls_used") // x86_64 버전
#endif


void print_console(const char* msg) {
	HANDLE stdOutHandle = NULL;

	stdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	WriteConsoleA(stdOutHandle, msg, strlen(msg), NULL, NULL);
};

void NTAPI TLS_CALLBACK1(PVOID tlsHandle, DWORD tlsReason, PVOID tlsReserved) {
	int a = 0;
	char msg[BUFSIZE] = { 0, };

	//MessageBoxA(NULL, "Test1", "Test1", NULL);
	wsprintfA(msg, "TLS_CALLBACK1() : handle = %X, reason = %d, a = %d\n", tlsHandle, tlsReason, a++);
	print_console(msg);
};

void NTAPI TLS_CALLBACK2(PVOID tlsHandle, DWORD tlsReason, PVOID tlsReserved) {
	char msg[BUFSIZE] = { 0, };

	//MessageBoxA(NULL, "Test2", "Test2", NULL);
	wsprintfA(msg, "TLS_CALLBACK2() : handle = %X, reason = %d\n", tlsHandle, tlsReason);
	print_console(msg);
};

#if X86
#pragma data_seg(".CRT$XLS")
EXTERN_C PIMAGE_TLS_CALLBACK TLS_CALLBACKsPoint[] = { TLS_CALLBACK1, TLS_CALLBACK2, 0 };
#else
#pragma const_seg(".CRT$XLS")
//EXTERN_C const PIMAGE_TLS_CALLBACK TLS_CALLBACKsPoint[] = { TLS_CALLBACK1, TLS_CALLBACK2, 0 };
EXTERN_C const PIMAGE_TLS_CALLBACK TLS_CALLBACKsPoint[] = { TLS_CALLBACK1, 0 };
#pragma const_seg()
#endif

#pragma comment(linker, "/INCLUDE:TLS_CALLBACKsPoint")

DWORD WINAPI ThreadProc(LPVOID lParam) {
	print_console("ThreadProc() start\n");
	print_console("ThreadProc() end\n");

	return 0;
};

int main(void) {
	HANDLE threadHandle = NULL;

	print_console("main() start\n");

	threadHandle = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
	WaitForSingleObject(threadHandle, 60 * 1000);
	CloseHandle(threadHandle);

	print_console("main() end\n");

	return 0;
};

#endif