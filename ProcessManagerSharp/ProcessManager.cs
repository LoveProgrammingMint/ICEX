using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessManagerSharp
{
    /// <summary>
    /// ProcessManager - C# 原生动态封装类
    /// 封装 ProcessManager.dll 的所有功能
    /// </summary>
    public class ProcessManager : IDisposable
    {
        #region Constants

        public const uint PM_SUCCESS = 0;
        public const uint PM_ERROR_INVALID_PARAMETER = 1;
        public const uint PM_ERROR_ACCESS_DENIED = 2;
        public const uint PM_ERROR_NOT_FOUND = 3;
        public const uint PM_ERROR_INSUFFICIENT_BUFFER = 4;
        public const uint PM_ERROR_OUT_OF_MEMORY = 5;
        public const uint PM_ERROR_NOT_SUPPORTED = 6;
        public const uint PM_ERROR_TIMEOUT = 7;
        public const uint PM_ERROR_UNKNOWN = 99;

        public const uint MAX_PATH = 260;
        public const uint MAX_PROCESS_NAME = 256;
        public const uint MAX_COMMAND_LINE = 32768;

        #endregion

        #region Native Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ProcessBasicInfo
        {
            public uint ProcessId;
            public uint ParentProcessId;
            public uint SessionId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ProcessName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string ImagePath;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32768)]
            public string CommandLine;
            [MarshalAs(UnmanagedType.Bool)]
            public bool IsWow64;
            [MarshalAs(UnmanagedType.Bool)]
            public bool IsProtected;
            [MarshalAs(UnmanagedType.Bool)]
            public bool IsBeingDebugged;
            public uint PriorityClass;
            public uint HandleCount;
            public uint ThreadCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessMemoryInfo
        {
            public ulong WorkingSetSize;
            public ulong PeakWorkingSetSize;
            public ulong PagefileUsage;
            public ulong PeakPagefileUsage;
            public ulong PrivateUsage;
            public ulong VirtualSize;
            public ulong PeakVirtualSize;
            public uint PageFaultCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessTimesInfo
        {
            public long CreationTime;
            public long ExitTime;
            public long KernelTime;
            public long UserTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadBasicInfo
        {
            public uint ThreadId;
            public uint ProcessId;
            public uint BasePriority;
            public uint Priority;
            public ulong StartAddress;
            public uint State;
            public uint WaitReason;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ModuleInfo
        {
            public ulong BaseAddress;
            public uint ModuleSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ModuleName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string ModulePath;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PrivilegeInfo
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Name;
            public uint Attributes;
            public uint LuidLow;
            public uint LuidHigh;
        }

        #endregion

        #region Native Methods

        private static class NativeMethods
        {
            private const string DLL_NAME = "ProcessManager.dll";

            // Process Enumeration
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmEnumProcesses(uint[] pProcessIds, uint dwArraySize, out uint pdwReturnedCount);

            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmGetProcessBasicInfo(uint dwProcessId, out ProcessBasicInfo pProcessInfo);

            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
            public static extern uint PmGetProcessImagePath(uint dwProcessId, StringBuilder lpImagePath, uint dwSize);

            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
            public static extern uint PmGetProcessCommandLine(uint dwProcessId, StringBuilder lpCommandLine, uint dwSize);

            // Process Control
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmTerminateProcess(uint dwProcessId, uint uExitCode);

            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool PmIsProcessRunning(uint dwProcessId);

            // Process Status
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmSuspendProcess(uint dwProcessId);

            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmResumeProcess(uint dwProcessId);

            // Memory Info
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmGetProcessMemoryInfo(uint dwProcessId, out ProcessMemoryInfo pMemoryInfo);

            // Process Times
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmGetProcessTimes(uint dwProcessId, out ProcessTimesInfo pTimesInfo);

            // Thread Enumeration
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmEnumProcessThreads(uint dwProcessId, uint[] pThreadIds, uint dwArraySize, out uint pdwReturnedCount);

            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmGetThreadBasicInfo(uint dwThreadId, out ThreadBasicInfo pThreadInfo);

            // Module Enumeration
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmEnumProcessModules(uint dwProcessId, [Out] ModuleInfo[] pModules, uint dwArraySize, out uint pdwReturnedCount);

            // Privilege Management
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmEnablePrivilege([MarshalAs(UnmanagedType.LPWStr)] string lpPrivilegeName);

            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi)]
            public static extern uint PmDisablePrivilege([MarshalAs(UnmanagedType.LPWStr)] string lpPrivilegeName);

            // Error Handling
            [DllImport(DLL_NAME, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
            public static extern uint PmGetLastErrorString(StringBuilder lpBuffer, uint dwSize);
        }

        #endregion

        #region Properties

        /// <summary>
        /// DLL路径
        /// </summary>
        public string? DllPath { get; private set; }

        /// <summary>
        /// 是否已初始化
        /// </summary>
        public bool IsInitialized { get; private set; }

        #endregion

        #region Constructors

        /// <summary>
        /// 默认构造函数
        /// </summary>
        public ProcessManager()
        {
            IsInitialized = true;
        }

        /// <summary>
        /// 指定DLL路径的构造函数
        /// </summary>
        /// <param name="dllPath">ProcessManager.dll的完整路径</param>
        public ProcessManager(string dllPath)
        {
            DllPath = dllPath;
            IsInitialized = true;
        }

        #endregion

        #region Process Enumeration Methods

        /// <summary>
        /// 枚举所有进程ID
        /// </summary>
        /// <returns>进程ID数组</returns>
        public uint[] EnumProcesses() 
        {
            uint[] processIds = new uint[1024];
            uint returnedCount;

            uint result = NativeMethods.PmEnumProcesses(processIds, (uint)processIds.Length, out returnedCount);
            ThrowIfError(result, "EnumProcesses");

            uint[] resultArray = new uint[returnedCount];
            Array.Copy(processIds, resultArray, (int)returnedCount);
            return resultArray;
        }

        /// <summary>
        /// 获取进程列表
        /// </summary>
        /// <returns>进程信息列表</returns>
        public List<ProcessInfo> GetProcessList()
        {
            var processes = new List<ProcessInfo>();
            uint[] processIds = EnumProcesses();

            foreach (uint pid in processIds)
            {
                try
                {
                    var info = GetProcessInfo(pid);
                    if (info != null)
                        processes.Add(info);
                }
                catch { }
            }

            return processes;
        }

        /// <summary>
        /// 获取进程基本信息
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>进程信息</returns>
        public ProcessInfo? GetProcessInfo(uint processId)
        {
            ProcessBasicInfo info;
            uint result = NativeMethods.PmGetProcessBasicInfo(processId, out info);
            
            if (result != PM_SUCCESS)
                return null;

            return new ProcessInfo
            {
                ProcessId = info.ProcessId,
                ParentProcessId = info.ParentProcessId,
                SessionId = info.SessionId,
                ProcessName = info.ProcessName,
                ImagePath = info.ImagePath,
                CommandLine = info.CommandLine,
                IsWow64 = info.IsWow64,
                IsProtected = info.IsProtected,
                IsBeingDebugged = info.IsBeingDebugged,
                PriorityClass = info.PriorityClass,
                HandleCount = info.HandleCount,
                ThreadCount = info.ThreadCount
            };
        }

        /// <summary>
        /// 通过名称查找进程
        /// </summary>
        /// <param name="processName">进程名称</param>
        /// <returns>匹配的进程列表</returns>
        public List<ProcessInfo> FindProcessesByName(string processName)
        {
            return GetProcessList()
                .Where(p => p.ProcessName?.IndexOf(processName, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();
        }

        /// <summary>
        /// 获取进程镜像路径
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>镜像路径</returns>
        public string GetProcessImagePath(uint processId)
        {
            StringBuilder sb = new StringBuilder((int)MAX_PATH);
            uint result = NativeMethods.PmGetProcessImagePath(processId, sb, MAX_PATH);
            ThrowIfError(result, "GetProcessImagePath");
            return sb.ToString();
        }

        /// <summary>
        /// 获取进程命令行
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>命令行字符串</returns>
        public string GetProcessCommandLine(uint processId)
        {
            StringBuilder sb = new StringBuilder((int)MAX_COMMAND_LINE);
            uint result = NativeMethods.PmGetProcessCommandLine(processId, sb, MAX_COMMAND_LINE);
            ThrowIfError(result, "GetProcessCommandLine");
            return sb.ToString();
        }

        #endregion

        #region Process Control Methods

        /// <summary>
        /// 终止进程
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <param name="exitCode">退出代码</param>
        public void TerminateProcess(uint processId, uint exitCode = 0)
        {
            uint result = NativeMethods.PmTerminateProcess(processId, exitCode);
            ThrowIfError(result, "TerminateProcess");
        }

        /// <summary>
        /// 检查进程是否正在运行
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>是否正在运行</returns>
        public bool IsProcessRunning(uint processId)
        {
            return NativeMethods.PmIsProcessRunning(processId);
        }

        /// <summary>
        /// 挂起进程
        /// </summary>
        /// <param name="processId">进程ID</param>
        public void SuspendProcess(uint processId)
        {
            uint result = NativeMethods.PmSuspendProcess(processId);
            ThrowIfError(result, "SuspendProcess");
        }

        /// <summary>
        /// 恢复进程
        /// </summary>
        /// <param name="processId">进程ID</param>
        public void ResumeProcess(uint processId)
        {
            uint result = NativeMethods.PmResumeProcess(processId);
            ThrowIfError(result, "ResumeProcess");
        }

        #endregion

        #region Memory Methods

        /// <summary>
        /// 获取进程内存信息
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>内存信息</returns>
        public MemoryInfo GetProcessMemoryInfo(uint processId)
        {
            ProcessMemoryInfo info;
            uint result = NativeMethods.PmGetProcessMemoryInfo(processId, out info);
            ThrowIfError(result, "GetProcessMemoryInfo");

            return new MemoryInfo
            {
                WorkingSetSize = info.WorkingSetSize,
                PeakWorkingSetSize = info.PeakWorkingSetSize,
                PagefileUsage = info.PagefileUsage,
                PeakPagefileUsage = info.PeakPagefileUsage,
                PrivateUsage = info.PrivateUsage,
                VirtualSize = info.VirtualSize,
                PeakVirtualSize = info.PeakVirtualSize,
                PageFaultCount = info.PageFaultCount
            };
        }

        #endregion

        #region Thread Methods

        /// <summary>
        /// 枚举进程线程
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>线程ID数组</returns>
        public uint[] EnumProcessThreads(uint processId)
        {
            uint[] threadIds = new uint[1024];
            uint returnedCount;

            uint result = NativeMethods.PmEnumProcessThreads(processId, threadIds, (uint)threadIds.Length, out returnedCount);
            ThrowIfError(result, "EnumProcessThreads");

            uint[] resultArray = new uint[returnedCount];
            Array.Copy(threadIds, resultArray, (int)returnedCount);
            return resultArray;
        }

        /// <summary>
        /// 获取线程基本信息
        /// </summary>
        /// <param name="threadId">线程ID</param>
        /// <returns>线程信息</returns>
        public ThreadInfo GetThreadInfo(uint threadId)
        {
            ThreadBasicInfo info;
            uint result = NativeMethods.PmGetThreadBasicInfo(threadId, out info);
            ThrowIfError(result, "GetThreadBasicInfo");

            return new ThreadInfo
            {
                ThreadId = info.ThreadId,
                ProcessId = info.ProcessId,
                BasePriority = info.BasePriority,
                Priority = info.Priority,
                StartAddress = info.StartAddress,
                State = info.State,
                WaitReason = info.WaitReason
            };
        }

        #endregion

        #region Module Methods

        /// <summary>
        /// 枚举进程模块
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>模块信息列表</returns>
        public List<ModuleInfoEx> EnumProcessModules(uint processId)
        {
            ModuleInfo[] modules = new ModuleInfo[256];
            uint returnedCount;

            uint result = NativeMethods.PmEnumProcessModules(processId, modules, (uint)modules.Length, out returnedCount);
            ThrowIfError(result, "EnumProcessModules");

            var list = new List<ModuleInfoEx>();
            for (int i = 0; i < returnedCount; i++)
            {
                list.Add(new ModuleInfoEx
                {
                    BaseAddress = modules[i].BaseAddress,
                    ModuleSize = modules[i].ModuleSize,
                    ModuleName = modules[i].ModuleName,
                    ModulePath = modules[i].ModulePath
                });
            }

            return list;
        }

        #endregion

        #region Privilege Methods

        /// <summary>
        /// 启用特权
        /// </summary>
        /// <param name="privilegeName">特权名称</param>
        public void EnablePrivilege(string privilegeName)
        {
            uint result = NativeMethods.PmEnablePrivilege(privilegeName);
            ThrowIfError(result, "EnablePrivilege");
        }

        /// <summary>
        /// 禁用特权
        /// </summary>
        /// <param name="privilegeName">特权名称</param>
        public void DisablePrivilege(string privilegeName)
        {
            uint result = NativeMethods.PmDisablePrivilege(privilegeName);
            ThrowIfError(result, "DisablePrivilege");
        }

        /// <summary>
        /// 启用调试特权
        /// </summary>
        public void EnableDebugPrivilege()
        {
            EnablePrivilege("SeDebugPrivilege");
        }

        #endregion

        #region Error Handling

        /// <summary>
        /// 获取最后一个错误信息
        /// </summary>
        /// <returns>错误信息字符串</returns>
        public string GetLastErrorString()
        {
            StringBuilder sb = new StringBuilder(512);
            NativeMethods.PmGetLastErrorString(sb, 512);
            return sb.ToString();
        }

        /// <summary>
        /// 将错误码转换为异常
        /// </summary>
        private void ThrowIfError(uint result, string operation)
        {
            if (result == PM_SUCCESS)
                return;

            string errorMessage = GetErrorMessage(result);
            throw new ProcessManagerException(operation, result, errorMessage);
        }

        /// <summary>
        /// 获取错误信息
        /// </summary>
        private string GetErrorMessage(uint errorCode)
        {
            switch (errorCode)
            {
                case PM_ERROR_INVALID_PARAMETER:
                    return "无效参数";
                case PM_ERROR_ACCESS_DENIED:
                    return "访问被拒绝";
                case PM_ERROR_NOT_FOUND:
                    return "未找到进程";
                case PM_ERROR_INSUFFICIENT_BUFFER:
                    return "缓冲区不足";
                case PM_ERROR_OUT_OF_MEMORY:
                    return "内存不足";
                case PM_ERROR_NOT_SUPPORTED:
                    return "不支持的操作";
                case PM_ERROR_TIMEOUT:
                    return "操作超时";
                case PM_ERROR_UNKNOWN:
                    return "未知错误";
                default:
                    return $"错误码: {errorCode}";
            }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            IsInitialized = false;
            GC.SuppressFinalize(this);
        }

        #endregion
    }

    #region Data Classes

    /// <summary>
    /// 进程信息类
    /// </summary>
    public class ProcessInfo
    {
        public uint ProcessId { get; set; }
        public uint ParentProcessId { get; set; }
        public uint SessionId { get; set; }
        public string? ProcessName { get; set; }
        public string? ImagePath { get; set; }
        public string? CommandLine { get; set; }
        public bool IsWow64 { get; set; }
        public bool IsProtected { get; set; }
        public bool IsBeingDebugged { get; set; }
        public uint PriorityClass { get; set; }
        public uint HandleCount { get; set; }
        public uint ThreadCount { get; set; }

        public override string ToString()
        {
            return $"{ProcessName} (PID: {ProcessId})";
        }
    }

    /// <summary>
    /// 内存信息类
    /// </summary>
    public class MemoryInfo
    {
        public ulong WorkingSetSize { get; set; }
        public ulong PeakWorkingSetSize { get; set; }
        public ulong PagefileUsage { get; set; }
        public ulong PeakPagefileUsage { get; set; }
        public ulong PrivateUsage { get; set; }
        public ulong VirtualSize { get; set; }
        public ulong PeakVirtualSize { get; set; }
        public uint PageFaultCount { get; set; }

        /// <summary>
        /// 工作集大小(MB)
        /// </summary>
        public double WorkingSetSizeMB => WorkingSetSize / (1024.0 * 1024.0);

        /// <summary>
        /// 私有内存大小(MB)
        /// </summary>
        public double PrivateUsageMB => PrivateUsage / (1024.0 * 1024.0);
    }

    /// <summary>
    /// 线程信息类
    /// </summary>
    public class ThreadInfo
    {
        public uint ThreadId { get; set; }
        public uint ProcessId { get; set; }
        public uint BasePriority { get; set; }
        public uint Priority { get; set; }
        public ulong StartAddress { get; set; }
        public uint State { get; set; }
        public uint WaitReason { get; set; }

        public override string ToString()
        {
            return $"TID: {ThreadId}, PID: {ProcessId}, Priority: {Priority}";
        }
    }

    /// <summary>
    /// 模块信息类
    /// </summary>
    public class ModuleInfoEx
    {
        public ulong BaseAddress { get; set; }
        public uint ModuleSize { get; set; }
        public string? ModuleName { get; set; }
        public string? ModulePath { get; set; }

        public override string ToString()
        {
            return $"{ModuleName} @ 0x{BaseAddress:X}";
        }
    }

    #endregion

    #region Exception

    /// <summary>
    /// ProcessManager异常类
    /// </summary>
    public class ProcessManagerException : Exception
    {
        public string Operation { get; }
        public uint ErrorCode { get; }

        public ProcessManagerException(string operation, uint errorCode, string message)
            : base($"[{operation}] {message}")
        {
            Operation = operation;
            ErrorCode = errorCode;
        }
    }

    #endregion
}
