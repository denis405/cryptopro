using NLog;

namespace CryptoPro.Helpers
{
    /// <summary>
    /// Доступ к логгерам
    /// </summary>
    public static class Log
    {
        /// <summary>
        /// DSS Log
        /// </summary>
        public static readonly Logger DssLogger = LogManager.GetLogger("DssLogger");
    }
}
