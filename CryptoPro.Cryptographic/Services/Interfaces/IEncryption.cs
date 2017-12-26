using System.Security.Cryptography;
using CryptoPro.Sharpei;

namespace CryptoPro.Cryptographic.Services.Interfaces
{
    /// <summary>
    /// Интерфейс для шифрования
    /// </summary>
    public interface IEncryptionService
    {
        /// <summary>
        /// Зашифровать симметричный ключ
        /// </summary>
        /// <param name="symmKey"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        byte[] EncryptSymmKey(Gost28147 symmKey, string recipientName);

        /// <summary>
        /// Расшифровать симметричный ключ
        /// </summary>
        /// <param name="symmKey"></param>
        /// <param name="recipientContainer"></param>
        /// <param name="isMachine"></param>
        /// <returns></returns>
        SymmetricAlgorithm DecryptSymmKey(byte[] symmKey, string recipientContainer, bool isMachine);

        /// <summary>
        /// Зашифровать строку
        /// </summary>
        /// <param name="data"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        byte[] EncryptData(string data, string recipientName);

        /// <summary>
        /// Зашифровать массив строк
        /// </summary>
        /// <param name="data"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        byte[] EncryptData(string[] data, string recipientName);

        /// <summary>
        /// Зашифровать массив байт
        /// </summary>
        /// <param name="data"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        byte[] EncryptData(byte[] data, string recipientName);

        /// <summary>
        /// Расшифровать данные
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        string DecryptString(byte[] data);

        /// <summary>
        /// Расшифровать массив данных
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        string[] DecryptStringArray(byte[] data);

        /// <summary>
        /// Расшифровать данные и получить массив байт
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        byte[] DecryptByteArray(byte[] data);
    }
}
