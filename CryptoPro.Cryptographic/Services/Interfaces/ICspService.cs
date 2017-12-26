using System.Security.Cryptography;

namespace CryptoPro.Cryptographic.Services.Interfaces
{
    /// <summary>
    /// Интерфейс CSP сервиса
    /// </summary>
    public interface ICspService
    {
        /// <summary>
        /// Зашифровать документ
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="encryptedFileName"></param>
        /// <param name="symmKey"></param>
        void EncryptDocument(string filename, string encryptedFileName, SymmetricAlgorithm symmKey);

        /// <summary>
        /// Расшифровать документ
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="decryptedFileName"></param>
        /// <param name="symmKey"></param>
        void DecryptDocument(string filename, string decryptedFileName, SymmetricAlgorithm symmKey);

        /// <summary>
        /// Зашифровать данные документа
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="symmKey"></param>
        /// <returns></returns>
        byte[] EncryptDocumentData(byte[] dataToEncrypt, SymmetricAlgorithm symmKey);

        /// <summary>
        /// Расшифровать данные документа
        /// </summary>
        /// <param name="dataToDecrypt"></param>
        /// <param name="symmKey"></param>
        /// <returns></returns>
        byte[] DecryptDocumentData(byte[] dataToDecrypt, SymmetricAlgorithm symmKey);

        /// <summary>
        /// Хэширование данных
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        byte[] ComputeHash(byte[] data);

        /// <summary>
        /// Хэширование файла
        /// </summary>
        /// <param name="filename"></param>
        /// <returns></returns>
        byte[] ComputeFileHash(string filename);
    }
}
