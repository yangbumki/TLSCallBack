#include <windows.h>

#if TLS_STRUCT

#endif

IMAGE_TLS_DIRECTORY


int main() {
	ShowWindow(GetConsoleWindow(), 0);
	MessageBoxA(NULL, "Hello :)", "Hello", NULL);
	return 0;
};