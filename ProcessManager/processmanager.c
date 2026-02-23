/*
 * ProcessManager DLL - Process Management Library Implementation
 * Based on ProcessHacker source code
 */

#include "ProcessManager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Helper Functions
// ============================================================================

static DWORD PmMapWin32Error(DWORD dwError)
{
    switch (dwError)
    {
        case ERROR_SUCCESS:
            return PM_SUCCESS;
        case ERROR_INVALID_PARAMETER:
            return PM_ERROR_INVALID_PARAMETER;
        case ERROR_ACCESS_DENIED:
            return PM_ERROR_ACCESS_DENIED;
        case ERROR_NOT_FOUND:
        case ERROR_FILE_NOT_FOUND:
            return PM_ERROR_NOT_FOUND;
        case ERROR_INSUFFICIENT_BUFFER:
            return PM_ERROR_INSUFFICIENT_BUFFER;
        case ERROR_OUTOFMEMORY:
        case ERROR_NOT_ENOUGH_MEMORY:
            return PM_ERROR_OUT_OF_MEMORY;
        case ERROR_NOT_SUPPORTED:
            return PM_ERROR_NOT_SUPPORTED;
        default:
            return PM_ERROR_UNKNOWN;
    }
}

static HANDLE PmOpenProcessInternal(DWORD dwProcessId, DWORD dwDesiredAccess)
{
    HANDLE hProcess = OpenProcess(dwDesiredAccess, FALSE, dwProcessId);
    return hProcess;
}

static BOOL PmGetProcessImagePathInternal(DWORD dwProcessId, LPWSTR lpImagePath, DWORD dwSize)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess)
        return FALSE;

    DWORD dwSizeNeeded = dwSize;
    BOOL result = QueryFullProcessImageNameW(hProcess, 0, lpImagePath, &dwSizeNeeded);
    
    CloseHandle(hProcess);
    return result;
}

static BOOL PmIsProcessWow64Internal(HANDLE hProcess, PBOOL pbIsWow64)
{
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandleW(L"kernel32"), "IsWow64Process");
    
    if (fnIsWow64Process == NULL)
    {
        *pbIsWow64 = FALSE;
        return TRUE;
    }
    
    return fnIsWow64Process(hProcess, pbIsWow64);
}

static BOOL PmGetProcessCommandLineInternal(DWORD dwProcessId, LPWSTR lpCommandLine, DWORD dwSize)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, 
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    if (!hProcess)
        return FALSE;

    // Get PEB address
    PM_PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
    );
    
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    
    if (!NtQueryInformationProcess)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Read PEB to get command line
    PM_PEB peb;
    PM_RTL_USER_PROCESS_PARAMETERS procParams;
    
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
    {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), &bytesRead))
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Read command line string
    WCHAR buffer[PM_MAX_COMMAND_LINE] = {0};
    DWORD bytesToRead = (DWORD)(procParams.CommandLine.Length);
    if (bytesToRead >= sizeof(buffer))
        bytesToRead = sizeof(buffer) - sizeof(WCHAR);
    
    if (ReadProcessMemory(hProcess, procParams.CommandLine.Buffer, buffer, bytesToRead, &bytesRead))
    {
        wcsncpy_s(lpCommandLine, dwSize, buffer, _TRUNCATE);
        CloseHandle(hProcess);
        return TRUE;
    }

    CloseHandle(hProcess);
    return FALSE;
}

// ============================================================================
// Process Enumeration
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcesses(
    _Out_writes_opt_(dwArraySize) PDWORD pProcessIds,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
)
{
    if (!pdwReturnedCount)
        return PM_ERROR_INVALID_PARAMETER;

    DWORD dwNeeded = 0;
    DWORD dwArraySizeInBytes = dwArraySize * sizeof(DWORD);
    
    if (!EnumProcesses(pProcessIds, dwArraySizeInBytes, &dwNeeded))
    {
        *pdwReturnedCount = 0;
        return PmMapWin32Error(GetLastError());
    }
    
    *pdwReturnedCount = dwNeeded / sizeof(DWORD);
    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcessesWithCallback(
    _In_ PM_ENUM_PROCESS_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    if (!Callback)
        return PM_ERROR_INVALID_PARAMETER;

    DWORD processes[1024];
    DWORD cbNeeded;
    DWORD cProcesses;
    
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
        return PmMapWin32Error(GetLastError());
    
    cProcesses = cbNeeded / sizeof(DWORD);
    
    for (DWORD i = 0; i < cProcesses; i++)
    {
        if (processes[i] == 0)
            continue;
            
        PM_PROCESS_BASIC_INFO info;
        if (PmGetProcessBasicInfo(processes[i], &info) == PM_SUCCESS)
        {
            if (!Callback(&info, Context))
                break;
        }
    }
    
    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessBasicInfo(
    _In_ DWORD dwProcessId,
    _Out_ PPM_PROCESS_BASIC_INFO pProcessInfo
)
{
    if (!pProcessInfo)
        return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pProcessInfo, sizeof(PM_PROCESS_BASIC_INFO));
    pProcessInfo->ProcessId = dwProcessId;

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess)
    {
        // Try with less access for system processes
        if (dwProcessId == 0 || dwProcessId == 4)
        {
            wcscpy_s(pProcessInfo->ProcessName, PM_MAX_PROCESS_NAME, 
                dwProcessId == 0 ? L"System Idle Process" : L"System");
            return PM_SUCCESS;
        }
        return PmMapWin32Error(GetLastError());
    }

    // Get process name
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
    {
        GetModuleBaseNameW(hProcess, hMod, pProcessInfo->ProcessName, PM_MAX_PROCESS_NAME);
    }

    // Get image path
    QueryFullProcessImageNameW(hProcess, 0, pProcessInfo->ImagePath, 
        &(DWORD){PM_MAX_PATH});

    // Get parent process ID and other info
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE, DWORD, PVOID, DWORD, PDWORD);
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    
    if (NtQueryInformationProcess)
    {
        PM_PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;
        if (NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength) == 0)
        {
            pProcessInfo->ParentProcessId = (DWORD)pbi.InheritedFromUniqueProcessId;
        }
    }

    // Get session ID
    ProcessIdToSessionId(dwProcessId, &pProcessInfo->SessionId);

    // Check if Wow64
    PmIsProcessWow64Internal(hProcess, &pProcessInfo->IsWow64);

    // Get priority class
    pProcessInfo->PriorityClass = GetPriorityClass(hProcess);

    // Get command line
    PmGetProcessCommandLineInternal(dwProcessId, pProcessInfo->CommandLine, PM_MAX_COMMAND_LINE);

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessImagePath(
    _In_ DWORD dwProcessId,
    _Out_writes_(dwSize) LPWSTR lpImagePath,
    _In_ DWORD dwSize
)
{
    if (!lpImagePath || dwSize == 0)
        return PM_ERROR_INVALID_PARAMETER;

    if (PmGetProcessImagePathInternal(dwProcessId, lpImagePath, dwSize))
        return PM_SUCCESS;

    return PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessCommandLine(
    _In_ DWORD dwProcessId,
    _Out_writes_(dwSize) LPWSTR lpCommandLine,
    _In_ DWORD dwSize
)
{
    if (!lpCommandLine || dwSize == 0)
        return PM_ERROR_INVALID_PARAMETER;

    if (PmGetProcessCommandLineInternal(dwProcessId, lpCommandLine, dwSize))
        return PM_SUCCESS;

    return PM_ERROR_ACCESS_DENIED;
}

// ============================================================================
// Process Control
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmCreateProcess(
    _In_ PPM_CREATE_PROCESS_PARAMS pParams,
    _Out_ PPM_CREATE_PROCESS_RESULT pResult
)
{
    if (!pParams || !pResult)
        return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pResult, sizeof(PM_CREATE_PROCESS_RESULT));

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    DWORD creationFlags = pParams->CreationFlags;
    if (pParams->StartSuspended)
        creationFlags |= CREATE_SUSPENDED;

    if (!CreateProcessW(
        pParams->ApplicationName,
        (LPWSTR)pParams->CommandLine,
        NULL,
        NULL,
        pParams->InheritHandles,
        creationFlags,
        NULL,
        pParams->WorkingDirectory,
        &si,
        &pi))
    {
        return PmMapWin32Error(GetLastError());
    }

    pResult->ProcessId = pi.dwProcessId;
    pResult->ThreadId = pi.dwThreadId;
    pResult->hProcess = pi.hProcess;
    pResult->hThread = pi.hThread;

    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmTerminateProcess(
    _In_ DWORD dwProcessId,
    _In_ UINT uExitCode
)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_TERMINATE);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    BOOL result = TerminateProcess(hProcess, uExitCode);
    CloseHandle(hProcess);

    return result ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API
BOOL
WINAPI
PmIsProcessRunning(
    _In_ DWORD dwProcessId
)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess)
        return FALSE;

    DWORD exitCode;
    BOOL result = GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);

    return result && exitCode == STILL_ACTIVE;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmSuspendProcess(
    _In_ DWORD dwProcessId
)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_SUSPEND_RESUME);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    typedef NTSTATUS (NTAPI *pNtSuspendProcess)(HANDLE);
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

PROCESSMANAGER_API
DWORD
WINAPI
PmResumeProcess(
    _In_ DWORD dwProcessId
)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_SUSPEND_RESUME);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    typedef NTSTATUS (NTAPI *pNtResumeProcess)(HANDLE);
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

PROCESSMANAGER_API
DWORD
WINAPI
PmWaitForProcessExit(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwTimeoutMs,
    _Out_opt_ PDWORD pdwExitCode
)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, SYNCHRONIZE | PROCESS_QUERY_INFORMATION);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    DWORD result = PM_SUCCESS;
    DWORD waitResult = WaitForSingleObject(hProcess, dwTimeoutMs);
    
    if (waitResult == WAIT_TIMEOUT)
        result = PM_ERROR_TIMEOUT;
    else if (waitResult == WAIT_FAILED)
        result = PmMapWin32Error(GetLastError());
    else if (pdwExitCode)
        GetExitCodeProcess(hProcess, pdwExitCode);

    CloseHandle(hProcess);
    return result;
}

// ============================================================================
// Process Information
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessMemoryInfo(
    _In_ DWORD dwProcessId,
    _Out_ PPM_PROCESS_MEMORY_INFO pMemoryInfo
)
{
    if (!pMemoryInfo)
        return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pMemoryInfo, sizeof(PM_PROCESS_MEMORY_INFO));

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

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

    // Get virtual memory info
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T virtualSize = 0;
    SIZE_T peakVirtualSize = 0;
    
    for (PBYTE addr = NULL; VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)); )
    {
        if (mbi.State == MEM_COMMIT)
            virtualSize += mbi.RegionSize;
        if ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize > peakVirtualSize)
            peakVirtualSize = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    pMemoryInfo->VirtualSize = virtualSize;
    pMemoryInfo->PeakVirtualSize = peakVirtualSize;

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessTimes(
    _In_ DWORD dwProcessId,
    _Out_ PPM_PROCESS_TIMES_INFO pTimesInfo
)
{
    if (!pTimesInfo)
        return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pTimesInfo, sizeof(PM_PROCESS_TIMES_INFO));

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser))
    {
        pTimesInfo->CreationTime.LowPart = ftCreation.dwLowDateTime;
        pTimesInfo->CreationTime.HighPart = ftCreation.dwHighDateTime;
        pTimesInfo->ExitTime.LowPart = ftExit.dwLowDateTime;
        pTimesInfo->ExitTime.HighPart = ftExit.dwHighDateTime;
        pTimesInfo->KernelTime.LowPart = ftKernel.dwLowDateTime;
        pTimesInfo->KernelTime.HighPart = ftKernel.dwHighDateTime;
        pTimesInfo->UserTime.LowPart = ftUser.dwLowDateTime;
        pTimesInfo->UserTime.HighPart = ftUser.dwHighDateTime;
    }

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessPriorityClass(
    _In_ DWORD dwProcessId,
    _Out_ PDWORD pdwPriorityClass
)
{
    if (!pdwPriorityClass)
        return PM_ERROR_INVALID_PARAMETER;

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    *pdwPriorityClass = GetPriorityClass(hProcess);
    CloseHandle(hProcess);

    return *pdwPriorityClass ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API
DWORD
WINAPI
PmSetProcessPriorityClass(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwPriorityClass
)
{
    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_SET_INFORMATION);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    BOOL result = SetPriorityClass(hProcess, dwPriorityClass);
    CloseHandle(hProcess);

    return result ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

// ============================================================================
// Thread Management
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcessThreads(
    _In_ DWORD dwProcessId,
    _Out_writes_opt_(dwArraySize) PDWORD pThreadIds,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
)
{
    if (!pdwReturnedCount)
        return PM_ERROR_INVALID_PARAMETER;

    *pdwReturnedCount = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return PmMapWin32Error(GetLastError());

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

PROCESSMANAGER_API
DWORD
WINAPI
PmGetThreadBasicInfo(
    _In_ DWORD dwThreadId,
    _Out_ PPM_THREAD_BASIC_INFO pThreadInfo
)
{
    if (!pThreadInfo)
        return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pThreadInfo, sizeof(PM_THREAD_BASIC_INFO));
    pThreadInfo->ThreadId = dwThreadId;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
    if (!hThread)
        return PmMapWin32Error(GetLastError());

    // Get thread times to get creation time
    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    if (GetThreadTimes(hThread, &ftCreation, &ftExit, &ftKernel, &ftUser))
    {
        // Basic info gathered
    }

    // Get priority
    pThreadInfo->Priority = GetThreadPriority(hThread);

    // Get start address (requires NtQueryInformationThread)
    typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
        HANDLE, DWORD, PVOID, DWORD, PDWORD);
    pNtQueryInformationThread NtQueryInformationThread = (pNtQueryInformationThread)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");

    if (NtQueryInformationThread)
    {
        ULONG_PTR startAddress = 0;
        ULONG returnLength;
        NtQueryInformationThread(hThread, 9, &startAddress, sizeof(startAddress), &returnLength);
        pThreadInfo->StartAddress = startAddress;
    }

    CloseHandle(hThread);
    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmSuspendThread(
    _In_ DWORD dwThreadId,
    _Out_opt_ PDWORD pdwSuspendCount
)
{
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, dwThreadId);
    if (!hThread)
        return PmMapWin32Error(GetLastError());

    DWORD result = SuspendThread(hThread);
    if (result != (DWORD)-1 && pdwSuspendCount)
        *pdwSuspendCount = result;

    CloseHandle(hThread);
    return result != (DWORD)-1 ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API
DWORD
WINAPI
PmResumeThread(
    _In_ DWORD dwThreadId,
    _Out_opt_ PDWORD pdwSuspendCount
)
{
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, dwThreadId);
    if (!hThread)
        return PmMapWin32Error(GetLastError());

    DWORD result = ResumeThread(hThread);
    if (result != (DWORD)-1 && pdwSuspendCount)
        *pdwSuspendCount = result;

    CloseHandle(hThread);
    return result != (DWORD)-1 ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

PROCESSMANAGER_API
DWORD
WINAPI
PmTerminateThread(
    _In_ DWORD dwThreadId,
    _In_ DWORD dwExitCode
)
{
    HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, dwThreadId);
    if (!hThread)
        return PmMapWin32Error(GetLastError());

    BOOL result = TerminateThread(hThread, dwExitCode);
    CloseHandle(hThread);

    return result ? PM_SUCCESS : PmMapWin32Error(GetLastError());
}

// ============================================================================
// Module Enumeration
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnumProcessModules(
    _In_ DWORD dwProcessId,
    _Out_writes_opt_(dwArraySize) PPM_MODULE_INFO pModules,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
)
{
    if (!pdwReturnedCount)
        return PM_ERROR_INVALID_PARAMETER;

    *pdwReturnedCount = 0;

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

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

PROCESSMANAGER_API
DWORD
WINAPI
PmGetModuleInfo(
    _In_ DWORD dwProcessId,
    _In_ LPCWSTR lpModuleName,
    _Out_ PPM_MODULE_INFO pModuleInfo
)
{
    if (!lpModuleName || !pModuleInfo)
        return PM_ERROR_INVALID_PARAMETER;

    ZeroMemory(pModuleInfo, sizeof(PM_MODULE_INFO));

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    HMODULE hMod = GetModuleHandleW(lpModuleName);
    if (!hMod)
    {
        // Try to find by enumerating
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                WCHAR modName[PM_MAX_PROCESS_NAME];
                if (GetModuleBaseNameW(hProcess, hMods[i], modName, PM_MAX_PROCESS_NAME))
                {
                    if (_wcsicmp(modName, lpModuleName) == 0)
                    {
                        hMod = hMods[i];
                        break;
                    }
                }
            }
        }
    }

    if (!hMod)
    {
        CloseHandle(hProcess);
        return PM_ERROR_NOT_FOUND;
    }

    MODULEINFO modInfo;
    if (GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo)))
    {
        pModuleInfo->BaseAddress = (ULONG_PTR)modInfo.lpBaseOfDll;
        pModuleInfo->ModuleSize = modInfo.SizeOfImage;
    }

    GetModuleBaseNameW(hProcess, hMod, pModuleInfo->ModuleName, PM_MAX_PROCESS_NAME);
    GetModuleFileNameExW(hProcess, hMod, pModuleInfo->ModulePath, PM_MAX_PATH);

    CloseHandle(hProcess);
    return PM_SUCCESS;
}

// ============================================================================
// Privilege Management
// ============================================================================

PROCESSMANAGER_API
DWORD
WINAPI
PmEnablePrivilege(
    _In_ LPCWSTR lpPrivilegeName
)
{
    if (!lpPrivilegeName)
        return PM_ERROR_INVALID_PARAMETER;

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

PROCESSMANAGER_API
DWORD
WINAPI
PmDisablePrivilege(
    _In_ LPCWSTR lpPrivilegeName
)
{
    if (!lpPrivilegeName)
        return PM_ERROR_INVALID_PARAMETER;

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

PROCESSMANAGER_API
DWORD
WINAPI
PmGetProcessPrivileges(
    _In_ DWORD dwProcessId,
    _Out_writes_opt_(dwArraySize) PPM_PRIVILEGE_INFO pPrivileges,
    _In_ DWORD dwArraySize,
    _Out_ PDWORD pdwReturnedCount
)
{
    if (!pdwReturnedCount)
        return PM_ERROR_INVALID_PARAMETER;

    *pdwReturnedCount = 0;

    HANDLE hProcess = PmOpenProcessInternal(dwProcessId, PROCESS_QUERY_INFORMATION);
    if (!hProcess)
        return PmMapWin32Error(GetLastError());

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return PmMapWin32Error(GetLastError());
    }

    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);

    if (dwLength == 0)
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return PM_SUCCESS;
    }

    PTOKEN_PRIVILEGES pTokenPrivs = (PTOKEN_PRIVILEGES)malloc(dwLength);
    if (!pTokenPrivs)
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return PM_ERROR_OUT_OF_MEMORY;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, dwLength, &dwLength))
    {
        free(pTokenPrivs);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return PmMapWin32Error(GetLastError());
    }

    *pdwReturnedCount = pTokenPrivs->PrivilegeCount;

    if (pPrivileges)
    {
        for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount && i < dwArraySize; i++)
        {
            pPrivileges[i].LuidLow = pTokenPrivs->Privileges[i].Luid.LowPart;
            pPrivileges[i].LuidHigh = pTokenPrivs->Privileges[i].Luid.HighPart;
            pPrivileges[i].Attributes = pTokenPrivs->Privileges[i].Attributes;

            WCHAR privName[PM_MAX_PROCESS_NAME];
            DWORD nameSize = PM_MAX_PROCESS_NAME;
            if (LookupPrivilegeNameW(NULL, &pTokenPrivs->Privileges[i].Luid, privName, &nameSize))
            {
                wcscpy_s(pPrivileges[i].Name, PM_MAX_PROCESS_NAME, privName);
            }
        }
    }

    free(pTokenPrivs);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return PM_SUCCESS;
}

// ============================================================================
// Error Handling
// ============================================================================

static WCHAR g_LastErrorMessage[512] = {0};

PROCESSMANAGER_API
DWORD
WINAPI
PmGetLastErrorString(
    _Out_writes_(dwSize) LPWSTR lpBuffer,
    _In_ DWORD dwSize
)
{
    if (!lpBuffer || dwSize == 0)
        return PM_ERROR_INVALID_PARAMETER;

    wcsncpy_s(lpBuffer, dwSize, g_LastErrorMessage, _TRUNCATE);
    return PM_SUCCESS;
}

PROCESSMANAGER_API
DWORD
WINAPI
PmSetLastErrorString(
    _In_ LPCWSTR lpMessage
)
{
    if (!lpMessage)
        return PM_ERROR_INVALID_PARAMETER;

    wcsncpy_s(g_LastErrorMessage, 512, lpMessage, _TRUNCATE);
    return PM_SUCCESS;
}
