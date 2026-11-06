using System;
using System.Runtime.InteropServices;

namespace WinSvcMgr
{
    internal static class DynApi
    {
        [DllImport("kernel32")]
        static extern IntPtr GetModuleHandle(string name);

        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string name);

        internal static string D(byte[] d, byte k)
        {
            char[] c = new char[d.Length];
            for (int i = 0; i < d.Length; i++)
                c[i] = (char)(d[i] ^ k);
            return new string(c);
        }

        internal static IntPtr Resolve(byte[] modEnc, byte[] funcEnc, byte key)
        {
            string modName = D(modEnc, key);
            IntPtr mod = GetModuleHandle(modName);
            if (mod == IntPtr.Zero)
                mod = LoadLibrary(modName);
            if (mod == IntPtr.Zero)
                return IntPtr.Zero;
            return GetProcAddress(mod, D(funcEnc, key));
        }

        internal static T GetFunc<T>(byte[] modEnc, byte[] funcEnc, byte key) where T : class
        {
            IntPtr addr = Resolve(modEnc, funcEnc, key);
            if (addr == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer(addr, typeof(T)) as T;
        }
    }
}
