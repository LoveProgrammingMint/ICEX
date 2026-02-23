/*
 * ProcessManager DLL - Process Management Library
 * Based on ProcessHacker source code
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

#ifdef __cplusplus
extern "C" {
#endif

#define PM_MAX_PATH                 260
#define PM_MAX_PROCESS_NAME         256
#define PM_MAX_COMMAND_LINE         32768

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
    } PM_PROCESS_BASIC_INFO, * PPM_PROCESS_BASIC_INFO;

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
    } PM_PROCESS_MEMORY_INFO, * PPM_PROCESS_MEMORY_INFO;

    // Thread basic information
    typedef struct _PM_THREAD_BASIC_INFO {
        DWORD   ThreadId;
        DWORD   ProcessId;
        DWORD   BasePriority;
        DWORD   Priority;
        ULONG_PTR StartAddress;
        DWORD   State;
        DWORD   WaitReason;
    } PM_THREAD_BASIC_INFO, * PPM_THREAD_BASIC_INFO;

    // Module information
    typedef struct _PM_MODULE_INFO {
        ULONG_PTR BaseAddress;
        ULONG   ModuleSize;
        WCHAR   ModuleName[PM_MAX_PROCESS_NAME];
        WCHAR   ModulePath[PM_MAX_PATH];
    } PM_MODULE_INFO, * PPM_MODULE_INFO;

    // ============================================================================
    // Process Enumeration Functions
    // ============================================================================

    PROCESSMANAGER_API DWORD WINAPI PmEnumProcesses(PDWORD pProcessIds, DWORD dwArraySize, PDWORD pdwReturnedCount);
    PROCESSMANAGER_API DWORD WINAPI PmGetProcessBasicInfo(DWORD dwProcessId, PPM_PROCESS_BASIC_INFO pProcessInfo);
    PROCESSMANAGER_API DWORD WINAPI PmGetProcessImagePath(DWORD dwProcessId, LPWSTR lpImagePath, DWORD dwSize);
    PROCESSMANAGER_API DWORD WINAPI PmGetProcessCommandLine(DWORD dwProcessId, LPWSTR lpCommandLine, DWORD dwSize);

    // ============================================================================
    // Process Control Functions
    // ============================================================================

    PROCESSMANAGER_API DWORD WINAPI PmTerminateProcess(DWORD dwProcessId, UINT uExitCode);
    PROCESSMANAGER_API BOOL WINAPI PmIsProcessRunning(DWORD dwProcessId);
    PROCESSMANAGER_API DWORD WINAPI PmSuspendProcess(DWORD dwProcessId);
    PROCESSMANAGER_API DWORD WINAPI PmResumeProcess(DWORD dwProcessId);

    // ============================================================================
    // Process Information Functions
    // ============================================================================

    PROCESSMANAGER_API DWORD WINAPI PmGetProcessMemoryInfo(DWORD dwProcessId, PPM_PROCESS_MEMORY_INFO pMemoryInfo);

    // ============================================================================
    // Thread Management Functions
    // ============================================================================

    PROCESSMANAGER_API DWORD WINAPI PmEnumProcessThreads(DWORD dwProcessId, PDWORD pThreadIds, DWORD dwArraySize, PDWORD pdwReturnedCount);
    PROCESSMANAGER_API DWORD WINAPI PmGetThreadBasicInfo(DWORD dwThreadId, PPM_THREAD_BASIC_INFO pThreadInfo);

    // ============================================================================
    // Module Enumeration Functions
    // ============================================================================

    PROCESSMANAGER_API DWORD WINAPI PmEnumProcessModules(DWORD dwProcessId, PPM_MODULE_INFO pModules, DWORD dwArraySize, PDWORD pdwReturnedCount);

    // ============================================================================
    // Privilege Management Functions
    // ============================================================================

    PROCESSMANAGER_API DWORD WINAPI PmEnablePrivilege(LPCWSTR lpPrivilegeName);
    PROCESSMANAGER_API DWORD WINAPI PmDisablePrivilege(LPCWSTR lpPrivilegeName);

    // ============================================================================
    // Error Handling Functions
    // ============================================================================

    PROCESSMANAGER_API DWORD WINAPI PmGetLastErrorString(LPWSTR lpBuffer, DWORD dwSize);

#ifdef __cplusplus
}
#endif

#endif // _PROCESS_MANAGER_H
