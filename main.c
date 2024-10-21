#include "win32.h"

void mainCRTStartup() {
	WINDOWS windows;
	windows_load(&windows);
	HANDLE stdout = windows.GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD written = 0;
	const char message[] = "Hello, world!\n";
	windows.WriteConsoleA(stdout, message, sizeof message - 1, &written, NULL);
	windows_unload(&windows);
}