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
