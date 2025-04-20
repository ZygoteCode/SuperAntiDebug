using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

public static class SuperAntiDebugCore
{
    private const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;
    private const uint FLG_HEAP_ENABLE_TAIL_CHECK = 0x10;
    private const uint FLG_HEAP_ENABLE_FREE_CHECK = 0x20;
    private const uint FLG_HEAP_VALIDATE_PARAMETERS = 0x40;
    private const uint NT_GLOBAL_FLAG_DEBUGGED = (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_KERNEL_DEBUGGER_INFORMATION
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelDebuggerEnabled;
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelDebuggerNotPresent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public uint ContextFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
    }

    public enum NtStatus : uint
    {
        Success = 0x00000000,
        Informational = 0x40000000,
        Error = 0xC0000000
    }

    public enum PROCESSINFOCLASS : int
    {
        ProcessBasicInformation = 0,
        ProcessDebugPort = 7,
        ProcessWow64Information = 26,
        ProcessImageFileName = 27,
        ProcessDebugObjectHandle = 30,
        ProcessDebugFlags = 31,
        ProcessBreakOnTermination = 29
    }

    public enum SYSTEM_INFORMATION_CLASS : int
    {
        SystemBasicInformation = 0,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemProcessInformation = 5,
        SystemProcessorPerformanceInformation = 8,
        SystemInterruptInformation = 23,
        SystemExceptionInformation = 33,
        SystemKernelDebuggerInformation = 35,
        SystemLookasideInformation = 45,
        SystemCodeIntegrityInformation = 103,
        SystemPolicyInformation = 134
    }

    public enum ThreadInformationClass : int
    {
        ThreadHideFromDebugger = 17
    }

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200),
        THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
        THREAD_ALL_ACCESS = 0x1F03FF
    }

    public enum DebugObjectInformationClass : int
    {
        DebugObjectFlags = 1,
        DebugObjectHandleCount = 2
    }

    #region Kernel32 Imports
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int OutputDebugString(string str);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetTickCount();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void RaiseException(uint dwExceptionCode, uint dwExceptionFlags, uint nNumberOfArguments, IntPtr lpArguments);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DebugActiveProcess(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DebugActiveProcessStop(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();
    #endregion

    #region Ntdll Imports
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtQueryInformationProcess(
        [In] IntPtr ProcessHandle,
        [In] PROCESSINFOCLASS ProcessInformationClass,
        IntPtr ProcessInformation,
        [In] int ProcessInformationLength,
        [Out][Optional] out int ReturnLength);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtClose([In] IntPtr Handle);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtRemoveProcessDebug(IntPtr ProcessHandle, IntPtr DebugObjectHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtSetInformationDebugObject(
        [In] IntPtr DebugObjectHandle,
        [In] DebugObjectInformationClass DebugObjectInformationClass,
        [In] IntPtr DebugObjectInformation,
        [In] int DebugObjectInformationLength,
        [Out][Optional] out int ReturnLength);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtQuerySystemInformation(
        [In] SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IntPtr SystemInformation,
        [In] int SystemInformationLength,
        [Out][Optional] out int ReturnLength);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtSetInformationThread(
        IntPtr ThreadHandle,
        ThreadInformationClass ThreadInformationClass,
        IntPtr ThreadInformation,
        int ThreadInformationLength);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtReadVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        [Out] byte[] Buffer,
        uint NumberOfBytesToRead,
        out uint NumberOfBytesRead);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NtStatus NtQueryObject(
        IntPtr Handle,
        int ObjectInformationClass,
        IntPtr ObjectInformation,
        int ObjectInformationLength,
        out int ReturnLength);

    #endregion

    public static bool RunChecks()
    {
        OllyDbgFormatStringExploit();
        PatchDbgBreakPoint();
        PatchDbgUiRemoteBreakin();

        return OutputDebugString("") > IntPtr.Size || Debugger.IsLogging() ||
            string.Compare(Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING"), "1", StringComparison.Ordinal) == 0 ||
            Process.GetCurrentProcess().Handle == IntPtr.Zero || Debugger.IsAttached ||
            CheckManagedDebugger() || CheckIsDebuggerPresent() || CheckRemoteDebuggerPresent() ||
            CheckProcessDebugPort() || CheckProcessDebugObjectHandle() ||
            CheckProcessDebugFlags() || CheckPebBeingDebugged() || CheckNtGlobalFlag() ||
            CheckKernelDebugger() || CheckHardwareRegisters() || CheckTimingGetTickCount() ||
            CheckTimingQueryPerformanceCounter() || CheckInt3() || CheckInt2D() ||
            CheckInstructionCounting() || CheckOutputDebugStringLastError() || CheckInvalidHandle() ||
            CheckParentProcess() || CheckDebuggerWindow() || CheckLoadedModules() ||
            CheckCommonDebuggerProcesses() || CheckForSandboxie() || CheckForVMWare() || CheckForVirtualBox();
    }

    public static bool HideCurrentThreadFromDebugger()
    {
        try
        {
            IntPtr hThread = GetCurrentThread();

            int currentManagedThreadId = Environment.CurrentManagedThreadId;
            ProcessThread currentProcessThread = null;
            foreach (ProcessThread pt in Process.GetCurrentProcess().Threads)
            {
                if (pt.Id == currentManagedThreadId)
                {
                    currentProcessThread = pt;
                    break;
                }
            }

            if (currentProcessThread != null)
            {
                IntPtr hRealThread = OpenThread(ThreadAccess.SET_INFORMATION, false, (uint)currentProcessThread.Id);
               
                if (hRealThread != IntPtr.Zero)
                {
                    NtStatus status = NtSetInformationThread(hRealThread, ThreadInformationClass.ThreadHideFromDebugger, IntPtr.Zero, 0);
                    CloseHandle(hRealThread);
                    return status == NtStatus.Success;
                }
                else
                {
                    NtStatus statusPseudo = NtSetInformationThread(hThread, ThreadInformationClass.ThreadHideFromDebugger, IntPtr.Zero, 0);
                    return statusPseudo == NtStatus.Success;
                }
            }
            else
            {
                return false;
            }

        }
        catch
        {
            return false;
        }
    }


    #region Basic Checks
    private static bool CheckManagedDebugger()
    {
        return Debugger.IsAttached;
    }

    private static bool CheckIsDebuggerPresent()
    {
        return IsDebuggerPresent();
    }

    private static bool CheckRemoteDebuggerPresent()
    {
        bool isDebuggerPresent = false;

        try
        {
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            return isDebuggerPresent;
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckInvalidHandle()
    {
        try
        {
            CloseHandle(IntPtr.Zero);
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckOutputDebugStringLastError()
    {
        OutputDebugString("just testing some stuff...");
        OutputDebugStringA("just testing some stuff...");

        if (Marshal.GetLastWin32Error() == 0)
        {
            return true;
        }

        return false;
    }

    [DllImport("kernel32.dll")]
    private static extern void SetLastError(uint dwErrCode);


    #endregion

    #region NtQueryInformationProcess Checks
    private static IntPtr GetPebAddress()
    {
        try
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            NtStatus status = NtQueryInformationProcess(
                Process.GetCurrentProcess().Handle,
                PROCESSINFOCLASS.ProcessBasicInformation,
                Marshal.AllocHGlobal(Marshal.SizeOf(pbi)),
                Marshal.SizeOf(pbi),
                out returnLength);

            if (status == NtStatus.Success)
            {
                IntPtr pbiPtr = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                try
                {
                    status = NtQueryInformationProcess(
                       Process.GetCurrentProcess().Handle,
                       PROCESSINFOCLASS.ProcessBasicInformation,
                       pbiPtr,
                       Marshal.SizeOf(pbi),
                       out returnLength);

                    if (status == NtStatus.Success)
                    {
                        pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pbiPtr, typeof(PROCESS_BASIC_INFORMATION));
                        return pbi.PebBaseAddress;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pbiPtr);
                }
            }
        }
        catch
        {

        }

        return IntPtr.Zero;
    }

    private static bool ReadRemoteByte(IntPtr address, out byte value)
    {
        value = 0;
        byte[] buffer = new byte[1];
        uint bytesRead;
        NtStatus status = NtReadVirtualMemory(Process.GetCurrentProcess().Handle, address, buffer, 1, out bytesRead);
      
        if (status == NtStatus.Success && bytesRead == 1)
        {
            value = buffer[0];
            return true;
        }

        return false;
    }

    private static bool ReadRemoteInt(IntPtr address, out uint value)
    {
        value = 0;
        byte[] buffer = new byte[sizeof(uint)];
        uint bytesRead;
        NtStatus status = NtReadVirtualMemory(Process.GetCurrentProcess().Handle, address, buffer, (uint)buffer.Length, out bytesRead);
       
        if (status == NtStatus.Success && bytesRead == buffer.Length)
        {
            value = BitConverter.ToUInt32(buffer, 0);
            return true;
        }

        return false;
    }


    private static bool CheckPebBeingDebugged()
    {
        IntPtr pebAddress = GetPebAddress();

        if (pebAddress == IntPtr.Zero)
        {
            return false;
        }

        IntPtr beingDebuggedAddr = IntPtr.Add(pebAddress, 0x2);

        if (ReadRemoteByte(beingDebuggedAddr, out byte beingDebuggedValue))
        {
            return beingDebuggedValue != 0;
        }
        return false;
    }

    private static bool CheckNtGlobalFlag()
    {
        IntPtr pebAddress = GetPebAddress();
        if (pebAddress == IntPtr.Zero) return false;

        int ntGlobalFlagOffset = Environment.Is64BitProcess ? 0xBC : 0x68;
        IntPtr ntGlobalFlagAddr = IntPtr.Add(pebAddress, ntGlobalFlagOffset);

        if (ReadRemoteInt(ntGlobalFlagAddr, out uint ntGlobalFlagValue))
        {
            return (ntGlobalFlagValue & NT_GLOBAL_FLAG_DEBUGGED) != 0;
        }
        return false;
    }


    private static bool CheckProcessDebugPort()
    {
        IntPtr debugPort = IntPtr.Zero;
        int returnLength;
        int size = IntPtr.Size;

        IntPtr hProcess = Process.GetCurrentProcess().Handle;
        IntPtr ptrDebugPort = Marshal.AllocHGlobal(size);

        try
        {
            NtStatus status = NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessDebugPort, ptrDebugPort, size, out returnLength);

            if (status == NtStatus.Success)
            {
                debugPort = Marshal.ReadIntPtr(ptrDebugPort); 
                return debugPort != IntPtr.Zero;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in CheckProcessDebugPort: {ex.Message}");
        }
        finally
        {
            Marshal.FreeHGlobal(ptrDebugPort);
        }
        return false;
    }

    private static bool CheckProcessDebugObjectHandle()
    {
        IntPtr debugHandle = IntPtr.Zero;
        int returnLength;
        int size = IntPtr.Size;

        IntPtr hProcess = Process.GetCurrentProcess().Handle;
        IntPtr ptrDebugHandle = Marshal.AllocHGlobal(size);

        try
        {
            NtStatus status = NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessDebugObjectHandle, ptrDebugHandle, size, out returnLength);

            if (status == NtStatus.Success)
            {
                debugHandle = Marshal.ReadIntPtr(ptrDebugHandle);
                if (debugHandle != IntPtr.Zero)
                {
                    NtStatus closeStatus = NtClose(debugHandle);
                    if (closeStatus == NtStatus.Success)
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                return false;
            }
            else if (status == (NtStatus)0xC0000353)
            {
                return false;
            }
        }
        catch
        {

        }
        finally
        {
            Marshal.FreeHGlobal(ptrDebugHandle);
        }

        return false;
    }


    private static bool CheckProcessDebugFlags()
    {
        uint debugFlags = 0;
        int returnLength;
        int size = sizeof(uint);

        IntPtr hProcess = Process.GetCurrentProcess().Handle;
        IntPtr ptrDebugFlags = Marshal.AllocHGlobal(size);

        try
        {
            NtStatus status = NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessDebugFlags, ptrDebugFlags, size, out returnLength);

            if (status == NtStatus.Success)
            {
                debugFlags = (uint)Marshal.ReadInt32(ptrDebugFlags);
                return debugFlags == 0;
            }
        }
        catch
        {

        }
        finally
        {
            Marshal.FreeHGlobal(ptrDebugFlags);
        }

        return false;
    }

    #endregion

    #region NtQuerySystemInformation Checks
    private static bool CheckKernelDebugger()
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = new SYSTEM_KERNEL_DEBUGGER_INFORMATION();
        int size = Marshal.SizeOf(skdi);
        IntPtr ptrSkdi = Marshal.AllocHGlobal(size);

        try
        {
            NtStatus status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation, ptrSkdi, size, out _);

            if (status == NtStatus.Success)
            {
                skdi = (SYSTEM_KERNEL_DEBUGGER_INFORMATION)Marshal.PtrToStructure(ptrSkdi, typeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION));
                return skdi.KernelDebuggerEnabled && !skdi.KernelDebuggerNotPresent;
            }
        }
        catch
        {

        }
        finally
        {
            Marshal.FreeHGlobal(ptrSkdi);
        }
        return false;
    }
    #endregion

    #region Hardware/CPU Checks
    private static bool CheckHardwareRegisters()
    {
        CONTEXT context = new CONTEXT();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        IntPtr hThread = GetCurrentThread();
        IntPtr hRealThread = OpenThread(ThreadAccess.GET_CONTEXT | ThreadAccess.QUERY_INFORMATION, false, GetCurrentWin32ThreadId());
        IntPtr threadHandleToUse = (hRealThread != IntPtr.Zero) ? hRealThread : hThread;

        try
        {
            if (GetThreadContext(threadHandleToUse, ref context))
            {
                return (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 || context.Dr6 != 0 || context.Dr7 != 0);
            }
        }
        catch
        {

        }
        finally
        {
            if (hRealThread != IntPtr.Zero)
            {
                CloseHandle(hRealThread);
            }
        }

        return false;
    }

    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();

    private static uint GetCurrentWin32ThreadId()
    {
        return GetCurrentThreadId();
    }

    #endregion

    #region Timing Checks
    private static bool CheckTimingGetTickCount()
    {
        long start = GetTickCount();
        Thread.Sleep(10);
        long end = GetTickCount();
        long delta = end - start;

        return delta > 500; 
    }

    private static bool CheckTimingQueryPerformanceCounter()
    {
        long freq;

        if (!QueryPerformanceFrequency(out freq))
        {
            return false;
        }

        long start, end;
        QueryPerformanceCounter(out start);
        Thread.Sleep(10);
        QueryPerformanceCounter(out end);

        double elapsedMs = (double)(end - start) * 1000.0 / freq;

        return elapsedMs > 500;
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryPerformanceFrequency(out long lpFrequency);

    #endregion

    #region Exception Checks
    private static bool CheckInt3()
    {
        try
        {
            RaiseException(0x80000003, 0, 0, IntPtr.Zero);
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckInt2D()
    {
        // INT 2D è usato internamente da Windows per il debugging kernel-mode,
        // ma può crashare il sistema se usato da user-mode senza privilegi.
        // Un debugger user-mode potrebbe intercettarlo. Molto rischioso. Non raccomandato.
        try
        {
            // Non eseguire questo codice in produzione!
            // RaiseException(0x????????, 0, 0, IntPtr.Zero); // Codice per INT 2D non standard user-mode
            return false; // Non implementato per sicurezza
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckInstructionCounting()
    {
        long startTicks = Stopwatch.GetTimestamp();

        int dummy = 0;

        for (int i = 0; i < 10000; i++)
        {
            dummy++;
        }

        long endTicks = Stopwatch.GetTimestamp();
        double elapsedMs = (double)(endTicks - startTicks) * 1000.0 / Stopwatch.Frequency;

        return elapsedMs > 10;
    }
    #endregion

    #region Process/Environment Checks
    private static bool CheckParentProcess()
    {
        try
        {
            IntPtr pbiPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));
            int returnLength;
            NtStatus status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, PROCESSINFOCLASS.ProcessBasicInformation, pbiPtr, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out returnLength);

            if (status != NtStatus.Success)
            {
                Marshal.FreeHGlobal(pbiPtr);
                return false;
            }

            PROCESS_BASIC_INFORMATION pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pbiPtr, typeof(PROCESS_BASIC_INFORMATION));
            Marshal.FreeHGlobal(pbiPtr);

            if (pbi.InheritedFromUniqueProcessId != IntPtr.Zero)
            {
                int parentPid = pbi.InheritedFromUniqueProcessId.ToInt32();
                Process parentProcess = Process.GetProcessById(parentPid);
                string parentName = parentProcess.ProcessName.ToLowerInvariant();

                string[] debuggerNames = { "devenv", "windbg", "ollydbg", "immunitydebugger", "idaq", "idaq64", "x64dbg", "x32dbg", "dnspy", "vsjitdebugger" };

                foreach (string name in debuggerNames)
                {
                    if (parentName.Contains(name))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {

        }

        return false;
    }

    private static bool CheckDebuggerWindow()
    {
        string[] classNames = { "OLLYDBG", "WinDbgFrameClass", "IDA View-A", "Qt5QWindowIcon" };
        bool found = false;

        EnumWindows((hWnd, lParam) =>
        {
            StringBuilder className = new StringBuilder(256);
            GetClassName(hWnd, className, className.Capacity);
            string cn = className.ToString();

            foreach (string name in classNames)
            {
                if (cn.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    found = true;
                    return false;
                }
            }
            return true;

        }, IntPtr.Zero);

        return found;
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    private static bool CheckLoadedModules()
    {
        Process currentProcess = Process.GetCurrentProcess();
        string[] debuggerModules = { "dbghelp.dll", "symsrv.dll", "ida", "olly", "windbg", "x64dbg", "x32dbg", "dnspy" /*aggiungere altri*/ };

        foreach (ProcessModule module in currentProcess.Modules)
        {
            string moduleNameLower = module.ModuleName.ToLowerInvariant();

            foreach (string name in debuggerModules)
            {
                if (moduleNameLower.Contains(name))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool CheckCommonDebuggerProcesses()
    {
        string[] debuggerProcesses = { "ollydbg", "windbg", "idaq", "idaq64", "immunitydebugger", "procmon", "processhacker", "x64dbg", "x32dbg", "dnspy", "fiddler" /* Anche tool di analisi */};
        Process[] processes = Process.GetProcesses();

        foreach (Process p in processes)
        {
            string processNameLower = p.ProcessName.ToLowerInvariant();

            foreach (string name in debuggerProcesses)
            {
                if (processNameLower.Contains(name))
                {
                    p.Dispose();
                    foreach (var proc in processes) { try { proc.Dispose(); } catch { } }
                    return true;
                }
            }

            p.Dispose();
        }
        return false;
    }

    #endregion

    #region Anti-VM / Anti-Sandbox Checks (Esempi basilari)

    private static bool CheckForSandboxie()
    {
        return GetModuleHandle("SbieDll.dll") != IntPtr.Zero;
    }

    private static bool CheckForVMWare()
    {
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI"))
            {
                if (key != null)
                {
                    foreach (string subkeyName in key.GetSubKeyNames())
                    {
                        if (subkeyName.Contains("VEN_15AD"))
                        {
                            return true;
                        }
                    }
                }
            }

            using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
            {
                foreach (var obj in searcher.Get())
                {
                    string manufacturer = obj["Manufacturer"]?.ToString().ToLower() ?? "";

                    if (manufacturer.Contains("vmware"))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {

        }
        return false;
    }

    private static bool CheckForVirtualBox()
    {
        try
        {
            if (GetModuleHandle("VBoxGuestHook.dll") != IntPtr.Zero)
            {
                return true;
            }

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\ACPI\DSDT\VBOX__"))
            {
                if (key != null)
                {
                    return true;
                }
            }

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System"))
            {
                if (key != null)
                {
                    string systemBiosVersion = key.GetValue("SystemBiosVersion")?.ToString().ToLower() ?? "";

                    if (systemBiosVersion.Contains("vbox"))
                    {
                        return true;
                    }

                    string videoBiosVersion = key.GetValue("VideoBiosVersion")?.ToString().ToLower() ?? "";

                    if (videoBiosVersion.Contains("virtualbox"))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {

        }

        return false;
    }

    #endregion

    #region Aggressive Techniques (Use with Extreme Caution)

    /// <summary>
    /// Tenta di patchare DbgBreakPoint in ntdll.dll con un RET (0xC3).
    /// Questo può impedire ai debugger standard di funzionare.
    /// Molto invasivo e potenzialmente rilevato da AV/EDR.
    /// </summary>
    private static bool PatchDbgBreakPoint()
    {
        try
        {
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");

            if (hNtdll == IntPtr.Zero)
            {
                return false;
            }

            IntPtr pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");

            if (pDbgBreakPoint == IntPtr.Zero)
            {
                return false;
            }

            byte[] retInstruction = { 0xC3 };
            uint oldProtect;
            IntPtr bytesWritten;

            if (VirtualProtectEx(Process.GetCurrentProcess().Handle, pDbgBreakPoint, (UIntPtr)retInstruction.Length, 0x40 /*PAGE_EXECUTE_READWRITE*/, out oldProtect))
            {
                bool success = WriteProcessMemory(Process.GetCurrentProcess().Handle, pDbgBreakPoint, retInstruction, (uint)retInstruction.Length, out bytesWritten);

                uint dummy;
                VirtualProtectEx(Process.GetCurrentProcess().Handle, pDbgBreakPoint, (UIntPtr)retInstruction.Length, oldProtect, out dummy);

                return success && bytesWritten.ToInt32() == retInstruction.Length;
            }
        }
        catch
        {

        }

        return false;
    }

    private static bool PatchDbgUiRemoteBreakin()
    {
        try
        {
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");

            if (hNtdll == IntPtr.Zero)
            {
                return false;
            }

            IntPtr pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");

            if (pDbgUiRemoteBreakin == IntPtr.Zero)
            {
                return false;
            }

            byte[] retInstruction = { 0xC3 };
            uint oldProtect;
            IntPtr bytesWritten;

            if (VirtualProtectEx(Process.GetCurrentProcess().Handle, pDbgUiRemoteBreakin, (UIntPtr)retInstruction.Length, 0x40, out oldProtect))
            {
                bool success = WriteProcessMemory(Process.GetCurrentProcess().Handle, pDbgUiRemoteBreakin, retInstruction, (uint)retInstruction.Length, out bytesWritten);
                uint dummy;
                VirtualProtectEx(Process.GetCurrentProcess().Handle, pDbgUiRemoteBreakin, (UIntPtr)retInstruction.Length, oldProtect, out dummy);
                return success && bytesWritten.ToInt32() == retInstruction.Length;
            }
        }
        catch
        {

        }

        return false;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern int OutputDebugStringA(string str);
    private static void OllyDbgFormatStringExploit()
    {
        OutputDebugStringA("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
    }

    #endregion
}