#ifndef WIN32_H
#define WIN32_H

#ifdef FALSE
#undef FALSE
#endif

#ifdef TRUE
#undef TRUE
#endif

#ifdef NULL
#undef NULL
#endif

#define FALSE 0
#define TRUE 1

#define NULL 0

typedef unsigned char BOOLEAN, BYTE, UCHAR, *PBYTE, *PUCHAR;
typedef unsigned short WORD, *PWORD, *LPWORD, USHORT;
typedef unsigned long DWORD, *PDWORD, *LPDWORD, ULONG;
typedef unsigned long long ULONGLONG, ULONG64, ULONG_PTR, SIZE_T;
typedef unsigned short WCHAR, *PWCHAR, *NWPSTR, *LPWSTR, *PWSTR;
typedef long LONG;
typedef const LPWSTR PCWSTR, LPCWSTR;
typedef void VOID, *PVOID, *LPVOID;
typedef const char* LPCSTR;
typedef void (*FARPROC)(void);
typedef PVOID HANDLE, HINSTANCE, HMODULE;
typedef int BOOL;

typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	ULONG      Length;
	BOOLEAN    Initialized;
	PVOID      SsHandle;
	LIST_ENTRY InLoaderOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID      EntryInProgress;
	BOOLEAN    ShutdownInProgress;
	HANDLE     ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	PVOID          DllBase;
	PVOID          EntryPoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG          Flags;
	USHORT         LoadCount;
	USHORT         TlsIndex;
	union {
		LIST_ENTRY   HashLinks;
		struct {
			PVOID      SectionPointer;
			ULONG      CheckSum;
		};
	};
	union {
		ULONG        TimeDateStamp;
		PVOID        LoadedImports;
	};
	PVOID          EntryPointActivationContext;
	PVOID          PatchInformation;
	LIST_ENTRY     ForwarderLinks;
	LIST_ENTRY     ServiceTagLinks;
	LIST_ENTRY     StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	BOOLEAN       InheritedAddressSpace;
	BOOLEAN       ReadImageFileExecOptions;
	BOOLEAN       BeingDebugged;
	UCHAR         ImageUsedLargePages : 1;
	UCHAR         IsProtectedProcess : 1;
	UCHAR         IsImageDynamicallyRelocated : 1;
	UCHAR         SkipPatchingUser32Forwarders : 1;
	UCHAR         IsPackagedProcess : 1;
	UCHAR         IsAppContainer : 1;
	UCHAR         IsProtectedProcessLight : 1;
	UCHAR         IsLongPathAwareProcess : 1;
	HANDLE        Mutant;
	HMODULE       ImageBaseAddress;
	PPEB_LDR_DATA LdrData;
} PEB, *PPEB;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Win64 TIB
typedef struct _NT_TIB {
	ULONG64 ExceptionList;
	ULONG64 StackBase;
	ULONG64 StackLimit;
	ULONG64 SubSystemTib;
	ULONG64 FiberData;
	ULONG64 ArbitraryUserPointer;
	ULONG64 Self;
} NT_TIB;

typedef struct _TEB {
	NT_TIB    Tib;
	PVOID     EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID     ActiveRpcHandle;
	PVOID     ThreadLocalStoragePointer;
	PPEB      Peb;
	// ...
} TEB, *PTEB;

typedef struct _IMAGE_DOS_HEADER {
	WORD  e_magic;
	WORD  e_cblp;
	WORD  e_cp;
	WORD  e_crlc;
	WORD  e_cparhdr;
	WORD  e_minalloc;
	WORD  e_maxalloc;
	WORD  e_ss;
	WORD  e_sp;
	WORD  e_csum;
	WORD  e_ip;
	WORD  e_cs;
	WORD  e_lfarlc;
	WORD  e_ovno;
	WORD  e_res[4];
	WORD  e_oemid;
	WORD  e_oeminfo;
	WORD  e_res2[10];
	DWORD e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD                 Magic; /* 0x20b */
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	ULONGLONG            ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD	Characteristics;
	DWORD	TimeDateStamp;
	WORD	MajorVersion;
	WORD	MinorVersion;
	DWORD	Name;
	DWORD	Base;
	DWORD	NumberOfFunctions;
	DWORD	NumberOfNames;
	DWORD	AddressOfFunctions;
	DWORD	AddressOfNames;
	DWORD	AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

#define STD_OUTPUT_HANDLE ((DWORD)-11)

typedef struct _KERNEL32 {
	HMODULE (*LoadLibraryA)(LPCSTR);
	BOOL    (*FreeLibrary)(HMODULE);
	FARPROC (*GetProcAddress)(HMODULE, LPCSTR);
} KERNEL32, *PKERNEL32;

typedef struct _WINDOWS {
	KERNEL32 kernel32;
	#define WIN32_DLL(name) HANDLE name ## _dll;
	#include "win32_imports.h"
	#undef WIN32_DLL
	#define WIN32_PROC(dll, name, ret, ...) ret (*name)(__VA_ARGS__);
	#include "win32_imports.h"
	#undef WIN32_PROC
} WINDOWS, *PWINDOWS;

BOOLEAN windows_load(PWINDOWS windows);
void windows_unload(PWINDOWS windows);

#endif // WIN32_H