using System;
using System.IO;

namespace WinSvcMgr.Core
{
    internal class ComHelper
    {
        private readonly static Guid IID_IUnknown = new Guid("{00000000-0000-0000-C000-000000000046}");

        public static int Process(Stream stm, Guid iid, out IntPtr ppv)
        {
            return WinApi.DecodeStream(new StreamWrapper(stm), ref iid, out ppv);
        }

        public static int Process(byte[] objref, out IntPtr ppv)
        {
            return Process(new MemoryStream(objref), IID_IUnknown, out ppv);
        }
    }
}
