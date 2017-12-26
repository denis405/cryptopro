using System.Security.Principal;

namespace CryptoPro.Helpers.Helpers
{
    /// <summary>
    /// 
    /// </summary>
    public class CurrentInfo
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public static bool IsMachine()
        {
            return WindowsIdentity.GetCurrent().Name.ToUpper().Contains("NT AUTHORITY\\СИСТЕМА") || WindowsIdentity.GetCurrent().Name.ToUpper().Contains("NT AUTHORITY\\SYSTEM");
        }
    }
}
