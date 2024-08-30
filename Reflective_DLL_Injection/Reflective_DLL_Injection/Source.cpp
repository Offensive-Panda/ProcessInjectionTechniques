#include <Windows.h>
#include <iostream>
#include <vector>
#include <memory>
#include "data.h"

void ReflectiveDLLInject(HANDLE hProcess, LPVOID dllBuffer, SIZE_T dllSize) {
    // Get pointers to in-memory DLL headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBuffer + dosHeader->e_lfanew);
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

    // Allocate memory for the DLL
    LPVOID dllBase = VirtualAllocEx(hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!dllBase) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        return;
    }

    // Copy the DLL image headers and sections to the newly allocated memory
    WriteProcessMemory(hProcess, dllBase, dllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDest = (LPVOID)((DWORD_PTR)dllBase + section->VirtualAddress);
        LPVOID sectionSrc = (LPVOID)((DWORD_PTR)dllBuffer + section->PointerToRawData);
        WriteProcessMemory(hProcess, sectionDest, sectionSrc, section->SizeOfRawData, NULL);
        section++;
    }

    // Perform base relocations
    IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size) {
        LPVOID relocBase = (LPVOID)((DWORD_PTR)dllBase + relocDir.VirtualAddress);
        DWORD_PTR delta = (DWORD_PTR)dllBase - ntHeaders->OptionalHeader.ImageBase;
        while (relocDir.Size > 0) {
            PBASE_RELOCATION_BLOCK block = (PBASE_RELOCATION_BLOCK)relocBase;
            DWORD blockSize = block->BlockSize;
            PBASE_RELOCATION_ENTRY entries = (PBASE_RELOCATION_ENTRY)((DWORD_PTR)block + sizeof(BASE_RELOCATION_BLOCK));

            for (DWORD i = 0; i < (blockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY); i++) {
                if (entries[i].Type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD_PTR* patchAddr = (DWORD_PTR*)((DWORD_PTR)dllBase + block->PageAddress + entries[i].Offset);
                    *patchAddr += delta;
                }
            }
            relocBase = (LPVOID)((DWORD_PTR)relocBase + blockSize);
            relocDir.Size -= blockSize;
        }
    }

    // Resolve imports
    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size) {
        LPVOID importDesc = (LPVOID)((DWORD_PTR)dllBase + importDir.VirtualAddress);
        PIMAGE_IMPORT_DESCRIPTOR importDescPtr = (PIMAGE_IMPORT_DESCRIPTOR)importDesc;
        while (importDescPtr->Name) {
            LPCSTR dllName = (LPCSTR)((DWORD_PTR)dllBase + importDescPtr->Name);
            HMODULE hImportDll = LoadLibraryA(dllName);
            if (hImportDll) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescPtr->FirstThunk);
                while (thunk->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                        DWORD ordinal = IMAGE_ORDINAL(thunk->u1.Ordinal);
                        thunk->u1.Function = (DWORD_PTR)GetProcAddress(hImportDll, (LPCSTR)ordinal);
                    }
                    else {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
                        thunk->u1.Function = (DWORD_PTR)GetProcAddress(hImportDll, importByName->Name);
                    }
                    thunk++;
                }
            }
            importDescPtr++;
        }
    }

    // Call DllMain
    DLLEntry entryPoint = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    entryPoint((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);

    std::cout << "DLL injected and executed successfully." << std::endl;
}

int main() {
    // Open DLL file and read it into memory
    HANDLE hFile = CreateFileA("panda.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open DLL file." << std::endl;
        return 1;
    }

    DWORD dllSize = GetFileSize(hFile, NULL);
    std::unique_ptr<BYTE[]> dllBuffer(new BYTE[dllSize]);
    DWORD bytesRead;
    if (!ReadFile(hFile, dllBuffer.get(), dllSize, &bytesRead, NULL)) {
        std::cerr << "Failed to read DLL file." << std::endl;
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    // Get handle to current process
    HANDLE hProcess = GetCurrentProcess();
    ReflectiveDLLInject(hProcess, dllBuffer.get(), dllSize);

    return 0;
}
