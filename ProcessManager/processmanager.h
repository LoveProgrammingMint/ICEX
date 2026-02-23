/*
 * ProcessManager DLL - Process Management Library
 * Based on ProcessHacker source code
 *
 * This DLL provides comprehensive process management functionality including:
 * - Process enumeration
 * - Process creation and termination
 * - Process information retrieval
 * - Process privilege management
 */

#ifndef _PROCESS_MANAGER_H
#define _PROCESS_MANAGER_H

#ifdef PROCESSMANAGER_EXPORTS
#define PROCESSMANAGER_API __declspec(dllexport)
#else
#define PROCESSMANAGER_API __declspec(dllimport)
#endif

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <ntsecapi.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants and Definitions
// ============================================================================

#define PM_MAX_PATH                 260
#define PM_MAX_PROCESS_NAME         256
#define PM_MAX_COMMAND_LINE         32768
#define PM_MAX_USER_NAME            256
#define PM_MAX_DOMAIN_NAME          256

// Process access rights (extended)
#define PM_PROCESS_QUERY_INFORMATION    0x0400
#define PM_PROCESS_QUERY_LIMITED_INFO   0x1000
#define PM_PROCESS_TERMINATE            0x0001
#define PM_PROCESS_SUSPEND_RESUME       0x0800
#define PM_PROCESS_VM_READ              0x0010
#define PM_PROCESS_VM_WRITE             0x0020
#define PM_PROCESS_VM_OPERATION         0x0008
#define PM_PROCESS_CREATE_THREAD        0x0002
#define PM_PROCESS_SET_INFORMATION      0x0200
#define PM_PROCESS_DUP_HANDLE           0x0040
#define PM_PROCESS_ALL_ACCESS           0x1F0FFF

// Process priority classes
#define PM_PRIORITY_CLASS_IDLE          4
#define PM_PRIORITY_CLASS_BELOW_NORMAL  6
#define PM_PRIORITY_CLASS_NORMAL        8
#define PM_PRIORITY_CLASS_ABOVE_NORMAL  10
#define PM_PRIORITY_CLASS_HIGH          13
#define PM_PRIORITY_CLASS_REALTIME      24

// Error codes
#define PM_SUCCESS                      0
#define PM_ERROR_INVALID_PARAMETER      1
#define PM_ERROR_ACCESS_DENIED          2
#define PM_ERROR_NOT_FOUND              3
#define PM_ERROR_INSUFFICIENT_BUFFER    4
#define PM_ERROR_OUT_OF_MEMORY          5
#define PM_ERROR_NOT_SUPPORTED          6
#define PM_ERROR_TIMEOUT                7
#define PM_ERROR_UNKNOWN                99

// ============================================================================
// NT Types and Structures (for internal use)
// ============================================================================

typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
typedef LONG KPRIORITY;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// UNICODE_STRING is already defined in ntsecapi.h, so we don't redefine it

typedef struct _PM_RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    UNICODE_STRING CurrentDirectory;
    HANDLE CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} PM_RTL_USER_PROCESS_PARAMETERS, *PPM_RTL_USER_PROCESS_PARAMETERS;

typedef struct _PM_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPM_RTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PM_PEB, *PPM_PEB;

typedef struct _PM_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPM_PEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PM_PROCESS_BASIC_INFORMATION, *PPM_PROCESS_BASIC_INFORMATION;

// ============================================================================
// Data Structures
// ============================================================================

// Basic process information
typedef struct _PM_PROCESS_BASIC_INFO {
    DWORD   ProcessId;
    DWORD   ParentProcessId;
    DWORD   SessionId;
    WCHAR   ProcessName[PM_MAX_PROCESS_NAME];
    WCHAR   ImagePath[PM_MAX_PATH];
    WCHAR   CommandLine[PM_MAX_COMMAND_LINE];
    BOOL    IsWow64;
    BOOL    IsProtected;
    BOOL    IsBeingDebugged;
    DWORD   PriorityClass;
    ULONG   HandleCount;
    ULONG   ThreadCount;
} PM_PROCESS_BASIC_INFO, *PPM_PROCESS_BASIC_INFO;

// Process memory information
typedef struct _PM_PROCESS_MEMORY_INFO {
    SIZE_T  WorkingSetSize;
    SIZE_T  PeakWorkingSetSize;
    SIZE_T  PagefileUsage;
    SIZE_T  PeakPagefileUsage;
    SIZE_T  PrivateUsage;
    SIZE_T  VirtualSize;
    SIZE_T  PeakVirtualSize;
    ULONG   PageFaultCount;
} PM_PROCESS_MEMORY_INFO, *PPM_PROCESS_MEMORY_INFO;

// Process times information
typedef struct _PM_PROCESS_TIMES_INFO {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} PM_PROCESS_TIMES_INFO, *PPM_PROCESS_TIMES_INFO;

// Thread basic information
typedef struct _PM_THREAD_BASIC_INFO {
    DWORD   ThreadId;
    DWORD   ProcessId;
    DWORD   BasePriority;
    DWORD   Priority;
    ULONG_PTR StartAddress;
    DWORD   State;
    DWORD   WaitReason;
} PM_THREAD_BASIC_INFO, *PPM_THREAD_BASIC_INFO;

// Module information
typedef struct _PM_MODULE_INFO {
    ULONG_PTR BaseAddress;
    ULONG   ModuleSize;
    WCHAR   ModuleName[PM_MAX_PROCESS_NAME];
    WCHAR   ModulePath[PM_MAX_PATH];
} PM_MODULE_INFO, *PPM_MODULE_INFO;

// Privilege information
typedef struct _PM_PRIVILEGE_INFO {
    WCHAR   Name[PM_MAX_PROCESS_NAME];
    DWORD   Attributes;
    DWORD   LuidLow;
    DWORD   LuidHigh;
} PM_PRIVILEGE_INFO, *PPM_PRIVILEGE_INFO;

// Create process parameters
typedef struct _PM_CREATE_PROCESS_PARAMS {
    LPCWSTR ApplicationName;
    LPCWSTR CommandLine;
    BOOL    InheritHandles;
    DWORD   CreationFlags;
    BOOL    StartSuspended;
    BOOL    RedirectStdOutput;
    BOOL    RedirectStdError;
    LPCWSTR WorkingDirectory;
    LPCWSTR Environment;
    WORD    ShowWindow;
} PM_CREATE_PROCESS_PARAMS, *PPM_CREATE_PROCESS_PARAMS;

// Create process result
typedef struct _PM_CREATE_PROCESS_RESULT {
    DWORD   ProcessId;
    DWORD   ThreadId;
    HANDLE  hProcess;
    HANDLE  hThread;
} PM_CREATE_PROCESS_RESULT, *PPM_CREATE_PROCESS_RESULT;

// Callback function for process enumeration
typedef BOOL (CALLBACK *PM_ENUM_PROCESS_CALLBACK)(
    _In_ PPM_PROCESS_BASIC_INFO pProcessInfo,
    _In_opt_ PVOID Context
);

// ============================================================================
// Process Enumeration Functions
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcesses(
    _Out_writes_opt_(dwArraySize) PDWORD pProcessIds,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
);

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcessesWithCallback(
    _In_ PM_ENUM_PROCESS_CALLBACK Callback,
    _In_opt_ PVOID Context
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessBasicInfo(
    _In_ DWORD dwProcessId,
    _Out_ PPM_PROCESS_BASIC_INFO pProcessInfo
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessImagePath(
    _In_ DWORD dwProcessId,
    _Out_writes_(dwSize) LPWSTR lpImagePath,
    _In_ DWORD dwSize
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessCommandLine(
    _In_ DWORD dwProcessId,
    _Out_writes_(dwSize) LPWSTR lpCommandLine,
    _In_ DWORD dwSize
);

// ============================================================================
// Process Control Functions
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmCreateProcess(
    _In_ PPM_CREATE_PROCESS_PARAMS pParams,
    _Out_ PPM_CREATE_PROCESS_RESULT pResult
);

PROCESSMANAGER_API
DWORD
WINAPI
PmTerminateProcess(
    _In_ DWORD dwProcessId,
    _In_ UINT uExitCode
);

PROCESSMANAGER_API
BOOL
WINAPI
PmIsProcessRunning(
    _In_ DWORD dwProcessId
);

PROCESSMANAGER_API
DWORD
WINAPI
PmSuspendProcess(
    _In_ DWORD dwProcessId
);

PROCESSMANAGER_API
DWORD
WINAPI
PmResumeProcess(
    _In_ DWORD dwProcessId
);

PROCESSMANAGER_API
DWORD
WINAPI
PmWaitForProcessExit(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwTimeoutMs,
    _Out_opt_ PDWORD pdwExitCode
);

// ============================================================================
// Process Information Functions
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessMemoryInfo(
    _In_ DWORD dwProcessId,
    _Out_ PPM_PROCESS_MEMORY_INFO pMemoryInfo
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessTimes(
    _In_ DWORD dwProcessId,
    _Out_ PPM_PROCESS_TIMES_INFO pTimesInfo
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessPriorityClass(
    _In_ DWORD dwProcessId,
    _Out_ PDWORD pdwPriorityClass
);

PROCESSMANAGER_API
DWORD
WINAPI
PmSetProcessPriorityClass(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwPriorityClass
);

// ============================================================================
// Thread Management Functions
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcessThreads(
    _In_ DWORD dwProcessId,
    _Out_writes_opt_(dwArraySize) PDWORD pThreadIds,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetThreadBasicInfo(
    _In_ DWORD dwThreadId,
    _Out_ PPM_THREAD_BASIC_INFO pThreadInfo
);

PROCESSMANAGER_API
DWORD
WINAPI
PmSuspendThread(
    _In_ DWORD dwThreadId,
    _Out_opt_ PDWORD pdwSuspendCount
);

PROCESSMANAGER_API
DWORD
WINAPI
PmResumeThread(
    _In_ DWORD dwThreadId,
    _Out_opt_ PDWORD pdwSuspendCount
);

PROCESSMANAGER_API
DWORD
WINAPI
PmTerminateThread(
    _In_ DWORD dwThreadId,
    _In_ DWORD dwExitCode
);

// ============================================================================
// Module Enumeration Functions
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcessModules(
    _In_ DWORD dwProcessId,
    _Out_writes_opt_(dwArraySize) PPM_MODULE_INFO pModules,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetModuleInfo(
    _In_ DWORD dwProcessId,
    _In_ LPCWSTR lpModuleName,
    _Out_ PPM_MODULE_INFO pModuleInfo
);

// ============================================================================
// Privilege Management Functions
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnablePrivilege(
    _In_ LPCWSTR lpPrivilegeName
);

PROCESSMANAGER_API
DWORD
WINAPI
PmDisablePrivilege(
    _In_ LPCWSTR lpPrivilegeName
);

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessPrivileges(
    _In_ DWORD dwProcessId,
    _Out_writes_opt_(dwArraySize) PPM_PRIVILEGE_INFO pPrivileges,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
);

// ============================================================================
// Error Handling Functions
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmGetLastErrorString(
    _Out_writes_(dwSize) LPWSTR lpBuffer,
    _In_ DWORD dwSize
);

PROCESSMANAGER_API
DWORD
WINAPI
PmSetLastErrorString(
    _In_ LPCWSTR lpMessage
);

#ifdef __cplusplus
}
#endif

#endif // _PROCESS_MANAGER_H
