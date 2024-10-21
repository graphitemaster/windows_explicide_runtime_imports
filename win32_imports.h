#ifndef WIN32_DLL
#define WIN32_DLL(...)
#endif
#ifndef WIN32_PROC
#define WIN32_PROC(...)
#endif

WIN32_DLL(kernel32)
  WIN32_PROC(kernel32, GetStdHandle, HANDLE, DWORD)
  WIN32_PROC(kernel32, WriteConsoleA, HANDLE, HANDLE, const VOID*, DWORD, LPDWORD, LPVOID)

#undef WIN32_DLL
#undef WIN32_PROC
