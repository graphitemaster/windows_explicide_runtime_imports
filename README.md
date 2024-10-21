# Explicit Windows Imports

A low-level technique for creating "freestanding" Windows executables, static libraries, and dynamic libraries.

When Windows executes a "Win32" or "Win64" process it sets up a variety of structures accessible from the GS segment register. In particular there is a [Thread Environment Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block) per-thread called the TEB accessible @ offset `0x30` and the TEB has a pointer to the [Process Environment Block](https://en.wikipedia.org/wiki/Process_Environment_Block) called the PEB. The PEB contains some data for the dynamic loader called `LdrData`. This data structure contains several intrusive doubly-linked lists for loaded "modules", which is what NT calls DLLs. We can walk the `InMemoryOrderModuleList` and search for `kernel32.dll` which is always mapped in the address space of every "Win32" and "Win64" process on Windows. Once we have the address of `kernel32.dll` we can start poking at the DOS header which every EXE and DLL begins with to find the offset to the [PE header](https://en.wikipedia.org/wiki/Portable_Executable#Technical_details) since all EXEs and DLLs are PE files. Once we have that header we can look through the "export directory" for a list of exported procedures. We are interested in reading only three procedures from `kernel32.dll`. The three procedures which form the basis of the dynamic loader itself.
  * `LoadLibraryA`
  * `FreeLibrary`
  * `GetProcAddress`

With these procedures it's possible to dynamically load any of the WinAPI libraries and use them without having any explicit import libraries needed during linking or runtime. This also lets us compile executables that are free of all [Runtime libraries](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#Runtime_libraries) including the C standard runtime library (MSVCP*.DLL), Universal C Run Time (UCRT) and the Microsoft Visual C++ Runtime.

This is especially useful for static libraries on Windows where linking against a static library often requires specifying multiple import libraries which that static library depend on. With this custom loader you can produce static libraries which can be linked against without any import libraries.

## How to use
The easiest way to use this is to include the three files into your project and to modify the `win32_imports.h` header file to explicitly list the procedures you want to import and from which DLLs using an [`XMACROS` approach](https://en.wikipedia.org/wiki/X_macro)

The `WIN32_DLL` macro is used to list the DLLs you'd like to import at runtime. It only takes a single argument which is the case-insensitive name of the DLL as a C identifier (not a string).

The `WIN32_PROC` macro is used to list the procedures you'd like to import at runtime. It takes a variable count of arguments but must expects the name of the DLL as defined by a previous `WIN32_DLL` macro to read the procedure from, the name of the procedure as a C identifier (not a string), the return type of that procedure and then a variable argument list of types for the procedure arguments.

Once you have done this you can load all your WinAPI DLLs and procedures with the following C code from the entry point of your application or library.
```c
WINDOWS windows;
windows_load(&windows);
```

You can completely unload the WinAPI runtime as well, something that is not typically possible within a process.
```c
windows_unload(&windows);
```

To make any WinAPI calls you'll do so indirectly through function pointers stored off the `WINDOWS` structure like
```c
windows.ProcedureName(...);
```

As you can see you cannot use the regular WinAPI headers for function prototypes. Instead it's encouraged you use the included `win32.h` header. You can define missing structures, typedefs, and constants for what you need here. You can then use them to define prototypes in the `win32_imports.h` header.

## Example
There is a minimal `"Hello, world!"` example included in this repo in `main.c`. You can compile it with `clang` on Windows or Linux with the following steps
```none
$ clang -target x86_64-unknown-windows -ffreestanding -nodefaultlibs -c main.c win32.c -O1
```

Linking can be done with either `lld-link` from clang
```none
$ lld-link main.o win32.o -subsystem:console # clang
```
Or using the included VS linker `link.exe`
```none
$ link main.o win32.o -subsystem:console # vs link
```

This should produce a rather lean ~2 KiB Win64 executable that prints `"Hello, world!"` to the console.