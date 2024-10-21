#include "win32.h"

// On MSVC there is a __readgsqword intrinsic, on mingw we use some inline asm.
#if defined(__MINGW32__) || defined(__clang__)
static inline ULONG64 __readgsqword(ULONG64 offset) {
	ULONG64 result;
	__asm__("movq %%gs:%[offset], %[result]"
		: [result] "=r" (result)
		: [offset] "m" ((*(ULONG64 *)offset)));
	return result;
}
#endif // __MINGW32__

static inline void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source) {
	target->Buffer = source;
	if (source) {
		SIZE_T length = 0;
		for (; source[length]; length++);
		length *= sizeof(WCHAR);
		if (length > 0xfffc) {
			length = 0xfffc;
		}
		target->Length = length;
		target->MaximumLength = target->Length + sizeof(WCHAR);
	} else {
		target->Length = 0;
		target->MaximumLength = 0;
	}
}

static inline LONG RtlCompareUnicodeStrings(const WCHAR *lhs, SIZE_T lhs_len,
                                            const WCHAR *rhs, SIZE_T rhs_len,
                                            BOOLEAN case_insensitive)
{
	LONG result = 0;
	SIZE_T len = lhs_len < rhs_len ? lhs_len : rhs_len;
	if (case_insensitive) {
		// Normally Windows would use NLS here to perform the case mapping based on
		// the locale but we can use an ASCII case map safely without any dependency.
		#define CASEMAP(ch) \
			(((ch) >= 'a' && (ch) <= 'z') ? (ch) - 32 : (ch))
		for (; result == 0 && len; lhs++, rhs++, len--) {
			result = CASEMAP(*lhs) - CASEMAP(*rhs);
		}
	} else while (result == 0 && len--) {
		result = *lhs++ - *rhs++;
	}
	return result == 0 ? lhs_len - rhs_len : result;
}

static inline LONG RtlCompareUnicodeString(const PUNICODE_STRING lhs,
                                           const PUNICODE_STRING rhs,
                                           BOOLEAN case_insensitive)
{
	return RtlCompareUnicodeStrings(lhs->Buffer, lhs->Length / sizeof(WCHAR),
	                                rhs->Buffer, rhs->Length / sizeof(WCHAR),
	                                case_insensitive);
}

static inline BOOLEAN RtlEqualUnicodeString(const PUNICODE_STRING lhs,
                                            const PUNICODE_STRING rhs,
                                            BOOLEAN case_insensitive)
{
	if (lhs->Length != rhs->Length) {
		return FALSE;
	}
	return !RtlCompareUnicodeString(lhs, rhs, case_insensitive);
}

static inline PVOID RVA(HMODULE module, DWORD va) {
	return (PVOID)((ULONG_PTR)(module) + va);
}

#define IMAGE_DOS_SIGNATURE           0x5a4d
#define IMAGE_NT_SIGNATURE            0x00004550
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

static inline const PIMAGE_NT_HEADERS64 RtlImageNtHeader(HMODULE module) {
	const PIMAGE_DOS_HEADER dos = (const PIMAGE_DOS_HEADER)(module);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const PIMAGE_NT_HEADERS64 nt = (const PIMAGE_NT_HEADERS64)((ULONG_PTR)(dos) + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	return nt;
}

static inline PVOID RtlImageDirectoryEntryToData(HMODULE module,
                                          BOOL image,
                                          WORD dir,
                                          ULONG *size)
{
	const PIMAGE_NT_HEADERS64 nt = RtlImageNtHeader(module);
	if (!nt) {
		return NULL;
	}
	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return NULL;
	}
	if (dir >= nt->OptionalHeader.NumberOfRvaAndSizes) {
		return NULL;
	}
	const PIMAGE_DATA_DIRECTORY directory = &nt->OptionalHeader.DataDirectory[dir];
	const DWORD address = directory->VirtualAddress;
	if (address == 0) {
		return NULL;
	}
	*size = directory->Size;
	if (image || address < nt->OptionalHeader.SizeOfHeaders) {
		return (PVOID)((ULONG_PTR)(module) + address);
	}
	return NULL;
}

static inline FARPROC RtlFindExportedRoutineByName(HMODULE module, LPCSTR name) {
	DWORD export_size = 0;
	const PIMAGE_EXPORT_DIRECTORY export_directory =
		RtlImageDirectoryEntryToData(module, TRUE, 0, &export_size);
	if (!export_directory || export_size < sizeof *export_directory) {
		return NULL;
	}
	// Binary search for the name in the exports list.
	const PWORD ordinals = (const PWORD)(RVA(module, export_directory->AddressOfNameOrdinals));
	const PDWORD names = (const PDWORD)(RVA(module, export_directory->AddressOfNames));
	DWORD min = 0;
	DWORD max = export_directory->NumberOfNames - 1;
	DWORD ordinal = -1;
	while (min <= max) {
		DWORD pos = (min + max) / 2;
		LPCSTR export_name = (LPCSTR)(RVA(module, names[pos]));
		PBYTE lhs = (PBYTE)(export_name);
		PBYTE rhs = (PBYTE)(name);
		for (; *lhs && *lhs == *rhs; lhs++, rhs++);
		const int dir = (*lhs > *rhs) - (*rhs > *lhs);
		if (dir == 0) {
			ordinal = ordinals[pos];
			break;
		} else if (dir > 0) {
			max = pos - 1;
		} else {
			min = pos + 1;
		}
	}
	if (ordinal == -1 || ordinal >= export_directory->NumberOfFunctions) {
		return NULL;
	}
	const PDWORD functions = (const PDWORD)(RVA(module, export_directory->AddressOfFunctions));
	const DWORD function = functions[ordinal];
	if (function == 0) {
		return NULL;
	}
	const ULONG_PTR proc = (const ULONG_PTR)(RVA(module, function));
	if (proc >= (const ULONG_PTR)(export_directory) &&
	    proc <  (const ULONG_PTR)(export_directory) + export_size)
	{
		return NULL;
	}
	return (FARPROC)(proc);
}

static inline PTEB NtCurrentTeb() {
	return (PTEB)__readgsqword(0x30);
}

static inline BOOLEAN load(PKERNEL32 kernel32) {
	const PTEB teb = NtCurrentTeb();
	const PPEB peb = teb->Peb;
	const PLIST_ENTRY tail = &peb->LdrData->InMemoryOrderModuleList;
	UNICODE_STRING NAME;
	RtlInitUnicodeString(&NAME, L"kernel32.dll");
	HMODULE module = NULL;
	for (PLIST_ENTRY node = tail->Flink; node != tail; node = node->Flink) {
		const PLDR_DATA_TABLE_ENTRY entry = (const PLDR_DATA_TABLE_ENTRY)(node - 1);
		const PUNICODE_STRING name = &entry->BaseDllName;
		const PWCHAR buffer = name->Buffer;
		if (RtlEqualUnicodeString(name, &NAME, TRUE)) {
			module = (HMODULE)(entry->DllBase);
			break;
		}
	}
	if (!module) {
		return FALSE;
	}
	*(FARPROC *)(&kernel32->LoadLibraryA)   = RtlFindExportedRoutineByName(module, "LoadLibraryA");
	*(FARPROC *)(&kernel32->FreeLibrary)    = RtlFindExportedRoutineByName(module, "FreeLibrary");
	*(FARPROC *)(&kernel32->GetProcAddress) = RtlFindExportedRoutineByName(module, "GetProcAddress");
	return TRUE;
}

BOOLEAN windows_load(PWINDOWS windows) {
	if (!load(&windows->kernel32)) {
		return FALSE;
	}
	#define WIN32_DLL(name) \
		if (!(windows->name ## _dll = windows->kernel32.LoadLibraryA(#name ".dll"))) { \
			return FALSE; \
		}
	#include "win32_imports.h"
	#define WIN32_PROC(dll, name, ret, ...) \
		if (!(*(FARPROC *)(&windows->name) = windows->kernel32.GetProcAddress(windows->dll ## _dll, #name))) { \
			return FALSE; \
		}
	#include "win32_imports.h"
	return TRUE;
}

void windows_unload(PWINDOWS windows) {
	#define WIN32_DLL(name) \
		windows->kernel32.FreeLibrary(windows->name ## _dll);
	#include "win32_imports.h"
	#undef WIN32_DLL
}