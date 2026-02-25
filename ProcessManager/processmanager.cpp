/*
 * ProcessManager DLL - Process Management Library Implementation
 */

#include "ProcessManager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

 // NT API typedefs
typedef LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

static DWORD PmMapWin32Error(DWORD dwError)
{
    switch (dwError)
    {
    case ERROR_SUCCESS: return PM_SUCCESS;
    case ERROR_INVALID_PARAMETER: return PM_ERROR_INVALID_PARAMETER;
    case ERROR_ACCESS_DENIED: return PM_ERROR_ACCESS_DENIED;
    case ERROR_NOT_FOUND:
    case ERROR_FILE_NOT_FOUND: return PM_ERROR_NOT_FOUND;
    case ERROR_INSUFFICIENT_BUFFER: return PM_ERROR_INSUFFICIENT_BUFFER;
    case ERROR_OUTOFMEMORY:
    case ERROR_NOT_ENOUGH_MEMORY: return PM_ERROR_OUT_OF_MEMORY;
    case ERROR_NOT_SUPPORTED: return PM_ERROR_NOT_SUPPORTED;
    default: return PM_ERROR_UNKNOWN;
    }
}

static HANDLE PmOpenProcessInternal(DWORD dwProcessId, DWORD dwDesiredAccess)
{
    return OpenProcess(dwDesiredAccess, FALSE, dwProcessId);
}

PROCESSMANAGER_API DWORD WINAPI PmEnumProcesses(PDWORD pProcessIds, DWORD dwArraySize, PDWORD pdwReturnedCount)
{
    if (!pdwReturnedCount) return PM_ERROR_INVALID_PARAMETER;

    DWORD dwNeeded = 0;
    if (!EnumProcesses(pProcessIds, dwArraySize * sizeof(DWORD), &dwNeeded))
    {
        *pdwReturnedCount = 0;
        return PmMapWin32Error(GetLastError());
    }

    *pdwReturnedCount = dwNeeded / sizeof(DWORD);
    return PM_SUCCESS;
}

PROCESSMANAGER_API DWORD WINAPI PmGetProcessBasicInfo(DWORD dwProcessId, PPM_PROCESS_BASIC_INFO pProcessInfo)
{
    if (!pProcessInfo) return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pProcessInfo, sizeof(PM_PROCESS_BASIC_INFO));
    pProcessInfo->ProcessId = dwProcessId;

    // Special handling for system processes
    if (dwProcessId == 0)
    {
        wcscpy_s(pProcessInfo->ProcessName, PM_MAX_PROCESS_NAME, L"System Idle Process");
        pProcessInfo->ThreadCount = 1;
        return PM_SUCCESS;
    }
    if (dwProcessId == 4)
    {
        wcscpy_s(pProcessInfo->ProcessName, PM_MAX_PROCESS_NAME, L"System");
        pProcessInfo->ThreadCount = 1;
        return PM_SUCCESS;
    }

    // Open process with query information access
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess)
    {
        hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION);
        if (!hProcess)
            return PmMapWin32Error(GetLastError());
    }

    // Get process name from module
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleBaseNameW(hProcess, hMod, pProcessInfo->ProcessName, PM_MAX_PROCESS_NAME);
    }

    // Get image path
    DWORD pathSize = PM_MAX_PATH;
    QueryFullProcessImageNameW(hProcess, 0, pProcessInfo->ImagePath, &pathSize);

    // Get session ID
    ProcessIdToSessionId(dwProcessId, &pProcessInfo->SessionId);

    // Check if Wow64
    BOOL isWow64 = FALSE;
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandleW(L"kernel32"), "IsWow64Process");
    if (fnIsWow64Process)
    {
        fnIsWow64Process(hProcess, &isWow64);
        pProcessInfo->IsWow64 = isWow64;
    }

    // Get priority class
    pProcessInfo->PriorityClass = GetPriorityClass(hProcess);

    // Get parent process ID using NtQueryInformationProcess
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, DWORD, PDWORD);
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

    if (NtQueryInformationProcess)
    {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;
        NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
        if (NT_SUCCESS(status))
        {
            pProcessInfo->ParentProcessId = (DWORD)pbi.InheritedFromUniqueProcessId;
        }
    }

    // Get handle count and thread count using NtQuerySystemInformation
    typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(DWORD, PVOID, ULONG, PULONG);
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    if (NtQuerySystemInformation)
    {
#define SystemProcessInformation 5

        ULONG bufferSize = 1024 * 1024;
        PVOID pSpi = malloc(bufferSize);

        if (pSpi)
        {
            NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, pSpi, bufferSize, NULL);

            if (NT_SUCCESS(status))
            {
                PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)pSpi;

                while (pCurrent)
                {
                    if ((DWORD)(ULONG_PTR)pCurrent->UniqueProcessId == dwProcessId)
                    {
                        pProcessInfo->HandleCount = pCurrent->HandleCount;
                        pProcessInfo->ThreadCount = pCurrent->NumberOfThreads;
                        break;
                    }

                    if (pCurrent->NextEntryOffset == 0)
                        break;

                    pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
                }
            }

            free(pSpi);
        }
    }

    // If we still don't have thread count, try using CreateToolhelp32Snapshot
    if (pProcessInfo->ThreadCount == 0)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &te32))
            {
                do
                {
                    if (te32.th32OwnerProcessID == dwProcessId)
                    {
                        pProcessInfo->ThreadCount++;
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }

            CloseHandle(hSnapshot);
        }
    }

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

PROCESSMANAGER_API DWORD WINAPI PmGetProcessImagePath(DWORD dwProcessId, LPWSTR lpImagePath, DWORD dwSize)
{
    if (!lpImagePath || dwSize == 0) return PM_ERROR_INVALID_PARAMETER;

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess) return PmMapWin32Error(GetLastError());

    DWORD size = dwSize;
    BOOL result = QueryFullProcessImageNameW(hProcess, 0, lpImagePath, &size);
    CloseHandle(hProcess);

    return result ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API DWORD WINAPI PmGetProcessCommandLine(DWORD dwProcessId, LPWSTR lpCommandLine, DWORD dwSize)
{
    if (!lpCommandLine || dwSize == 0) return PM_ERROR_INVALID_PARAMETER;

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    if (!hProcess) return PM_ERROR_ACCESS_DENIED;

    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, DWORD, PDWORD);
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess)
    {
        CloseHandle(hProcess);
        return PM_ERROR_NOT_SUPPORTED;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);

    if (!NT_SUCCESS(status))
    {
        CloseHandle(hProcess);
        return PM_ERROR_ACCESS_DENIED;
    }

    PVOID pebAddr = pbi.PebBaseAddress;
    PVOID processParamsAddr = NULL;
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, (PBYTE)pebAddr + 0x20, &processParamsAddr, sizeof(processParamsAddr), &bytesRead))
    {
        CloseHandle(hProcess);
        return PM_ERROR_ACCESS_DENIED;
    }

    UNICODE_STRING commandLine;
    if (!ReadProcessMemory(hProcess, (PBYTE)processParamsAddr + 0x70, &commandLine, sizeof(commandLine), &bytesRead))
    {
        CloseHandle(hProcess);
        return PM_ERROR_ACCESS_DENIED;
    }

    DWORD bytesToRead = (DWORD)(commandLine.Length);
    if (bytesToRead >= dwSize * sizeof(WCHAR))
        bytesToRead = (dwSize - 1) * sizeof(WCHAR);

    if (bytesToRead > 0 && ReadProcessMemory(hProcess, commandLine.Buffer, lpCommandLine, bytesToRead, &bytesRead))
    {
        lpCommandLine[bytesToRead / sizeof(WCHAR)] = L'\0';
    }
    else
    {
        lpCommandLine[0] = L'\0';
    }

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

PROCESSMANAGER_API DWORD WINAPI PmTerminateProcess(DWORD dwProcessId, UINT uExitCode)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_TERMINATE);
    if (!hProcess) return PmMapWin32Error(GetLastError());

    BOOL result = TerminateProcess(hProcess, uExitCode);
    CloseHandle(hProcess);

    return result ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API BOOL WINAPI PmIsProcessRunning(DWORD dwProcessId)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess) return FALSE;

    DWORD exitCode;
    BOOL result = GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);

    return result && exitCode == STILL_ACTIVE;
}

PROCESSMANAGER_API DWORD WINAPI PmSuspendProcess(DWORD dwProcessId)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_SUSPEND_RESUME);
    if (!hProcess) return PmMapWin32Error(GetLastError());

    typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE);
    pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");

    DWORD result = PM_ERROR_NOT_SUPPORTED;
    if (NtSuspendProcess)
    {
        NTSTATUS status = NtSuspendProcess(hProcess);
        result = NT_SUCCESS(status) ? PM_SUCCESS : PM_ERROR_ACCESS_DENIED;
    }

    CloseHandle(hProcess);
    return result;
}

PROCESSMANAGER_API DWORD WINAPI PmResumeProcess(DWORD dwProcessId)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_SUSPEND_RESUME);
    if (!hProcess) return PmMapWin32Error(GetLastError());

    typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE);
    pNtResumeProcess NtResumeProcess = (pNtResumeProcess)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess");

    DWORD result = PM_ERROR_NOT_SUPPORTED;
    if (NtResumeProcess)
    {
        NTSTATUS status = NtResumeProcess(hProcess);
        result = NT_SUCCESS(status) ? PM_SUCCESS : PM_ERROR_ACCESS_DENIED;
    }

    CloseHandle(hProcess);
    return result;
}

PROCESSMANAGER_API DWORD WINAPI PmGetProcessMemoryInfo(DWORD dwProcessId, PPM_PROCESS_MEMORY_INFO pMemoryInfo)
{
    if (!pMemoryInfo) return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pMemoryInfo, sizeof(PM_PROCESS_MEMORY_INFO));

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    if (!hProcess) return PmMapWin32Error(GetLastError());

    PROCESS_MEMORY_COUNTERS_EX pmcex;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmcex, sizeof(pmcex)))
    {
        pMemoryInfo->WorkingSetSize = pmcex.WorkingSetSize;
        pMemoryInfo->PeakWorkingSetSize = pmcex.PeakWorkingSetSize;
        pMemoryInfo->PagefileUsage = pmcex.PagefileUsage;
        pMemoryInfo->PeakPagefileUsage = pmcex.PeakPagefileUsage;
        pMemoryInfo->PrivateUsage = pmcex.PrivateUsage;
        pMemoryInfo->PageFaultCount = pmcex.PageFaultCount;
    }

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

PROCESSMANAGER_API DWORD WINAPI PmEnumProcessThreads(DWORD dwProcessId, PDWORD pThreadIds, DWORD dwArraySize, PDWORD pdwReturnedCount)
{
    if (!pdwReturnedCount) return PM_ERROR_INVALID_PARAMETER;

    *pdwReturnedCount = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return PmMapWin32Error(GetLastError());

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
    {
        CloseHandle(hSnapshot);
        return PmMapWin32Error(GetLastError());
    }

    DWORD count = 0;
    do
    {
        if (te32.th32OwnerProcessID == dwProcessId)
        {
            if (pThreadIds && count < dwArraySize)
                pThreadIds[count] = te32.th32ThreadID;
            count++;
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    *pdwReturnedCount = count;

    return PM_SUCCESS;
}

PROCESSMANAGER_API DWORD WINAPI PmGetThreadBasicInfo(DWORD dwThreadId, PPM_THREAD_BASIC_INFO pThreadInfo)
{
    if (!pThreadInfo) return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pThreadInfo, sizeof(PM_THREAD_BASIC_INFO));
    pThreadInfo->ThreadId = dwThreadId;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
    if (!hThread) return PmMapWin32Error(GetLastError());

    pThreadInfo->Priority = GetThreadPriority(hThread);

    CloseHandle(hThread);
    return PM_SUCCESS;
}

PROCESSMANAGER_API DWORD WINAPI PmEnumProcessModules(DWORD dwProcessId, PPM_MODULE_INFO pModules, DWORD dwArraySize, PDWORD pdwReturnedCount)
{
    if (!pdwReturnedCount) return PM_ERROR_INVALID_PARAMETER;

    *pdwReturnedCount = 0;

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    if (!hProcess) return PmMapWin32Error(GetLastError());

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        CloseHandle(hProcess);
        return PmMapWin32Error(GetLastError());
    }

    DWORD numModules = cbNeeded / sizeof(HMODULE);
    *pdwReturnedCount = numModules;

    if (pModules)
    {
        for (DWORD i = 0; i < numModules && i < dwArraySize; i++)
        {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            {
                pModules[i].BaseAddress = (ULONG_PTR)modInfo.lpBaseOfDll;
                pModules[i].ModuleSize = modInfo.SizeOfImage;
            }

            GetModuleBaseNameW(hProcess, hMods[i], pModules[i].ModuleName, PM_MAX_PROCESS_NAME);
            GetModuleFileNameExW(hProcess, hMods[i], pModules[i].ModulePath, PM_MAX_PATH);
        }
    }

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

PROCESSMANAGER_API DWORD WINAPI PmEnablePrivilege(LPCWSTR lpPrivilegeName)
{
    if (!lpPrivilegeName) return PM_ERROR_INVALID_PARAMETER;

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return PmMapWin32Error(GetLastError());

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, lpPrivilegeName, &luid))
    {
        CloseHandle(hToken);
        return PmMapWin32Error(GetLastError());
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return result ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API DWORD WINAPI PmDisablePrivilege(LPCWSTR lpPrivilegeName)
{
    if (!lpPrivilegeName) return PM_ERROR_INVALID_PARAMETER;

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return PmMapWin32Error(GetLastError());

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, lpPrivilegeName, &luid))
    {
        CloseHandle(hToken);
        return PmMapWin32Error(GetLastError());
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return result ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

static WCHAR g_LastErrorMessage[512] = { 0 };

PROCESSMANAGER_API DWORD WINAPI PmGetLastErrorString(LPWSTR lpBuffer, DWORD dwSize)
{
    if (!lpBuffer || dwSize == 0) return PM_ERROR_INVALID_PARAMETER;
    wcsncpy_s(lpBuffer, dwSize, g_LastErrorMessage, _TRUNCATE);
    return PM_SUCCESS;
}
