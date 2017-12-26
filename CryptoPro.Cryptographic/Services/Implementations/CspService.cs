using System;
using System.IO;
using System.Security.Cryptography;
using CryptoPro.Cryptographic.Services.Interfaces;

namespace CryptoPro.Cryptographic.Services.Implementations
{
    /// <summary>
    /// CSP сервис
    /// </summary>
    public class CspService : ICspService
    {
        /// <summary>
        /// 
        /// </summary>
        public CspService()
        {
            
        }

        /// <summary>
        /// Зашифровать документ
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="encryptedFileName"></param>
        /// <param name="symmKey"></param>
        public void EncryptDocument(string filename, string encryptedFileName, SymmetricAlgorithm symmKey)
        {
            using (FileStream ofs = new FileStream(encryptedFileName, FileMode.Create))
            {
                // Создаем поток шифратора.
                ICryptoTransform transform = symmKey.CreateEncryptor();

                // Создаем поток шифрования для записи в файл.
                using (CryptoStream cs = new CryptoStream(ofs, transform, CryptoStreamMode.Write))
                {
                    byte[] data = new byte[4096];
                    // Открываем входной файл.
                    using (FileStream ifs = new FileStream(filename, FileMode.Open, FileAccess.Read))
                    {
                        // и переписываем содержимое в выходной поток.
                        int length = ifs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            cs.Write(data, 0, length);
                            length = ifs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Расшифровать документ
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="decryptedFileName"></param>
        /// <param name="symmKey"></param>
        public void DecryptDocument(string filename, string decryptedFileName, SymmetricAlgorithm symmKey)
        {
            // Открываем зашифрованный файл.
            using (FileStream ifs = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                // Создаем поток разшифрования.
                ICryptoTransform transform = symmKey.CreateDecryptor();

                // Создаем поток разшифрования из файла.
                using (CryptoStream cs = new CryptoStream(ifs, transform, CryptoStreamMode.Read))
                {
                    // Открываем расшифрованный файл
                    using (FileStream ofs = new FileStream(decryptedFileName, FileMode.Create))
                    {
                        byte[] data = new byte[4096];
                        // и переписываем содержимое в выходной поток.
                        int length = cs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            ofs.Write(data, 0, length);
                            length = cs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Зашифровать данные документа
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="symmKey"></param>
        /// <returns></returns>
        public byte[] EncryptDocumentData(byte[] dataToEncrypt, SymmetricAlgorithm symmKey)
        {
            byte[] encData = new byte[dataToEncrypt.Length];

            using (MemoryStream ofs = new MemoryStream(encData))
            {
                // Создаем поток шифратора.
                ICryptoTransform transform = symmKey.CreateEncryptor();

                // Создаем поток шифрования для записи в файл.
                using (CryptoStream cs = new CryptoStream(ofs, transform, CryptoStreamMode.Write))
                {
                    byte[] data = new byte[4096];
                    // Открываем входной файл.
                    using (MemoryStream ifs = new MemoryStream(dataToEncrypt))
                    {
                        // и переписываем содержимое в выходной поток.
                        int length = ifs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            cs.Write(data, 0, length);
                            length = ifs.Read(data, 0, data.Length);
                        }
                    }
                }
            }

            return encData;
        }

        /// <summary>
        /// Расшифровать данные документа
        /// </summary>
        /// <param name="dataToDecrypt"></param>
        /// <param name="symmKey"></param>
        /// <returns></returns>
        public byte[] DecryptDocumentData(byte[] dataToDecrypt, SymmetricAlgorithm symmKey)
        {
            byte[] decData = new byte[dataToDecrypt.Length];

            // Открываем зашифрованный файл.
            using (MemoryStream ifs = new MemoryStream(dataToDecrypt))
            {
                // Создаем поток разшифрования.
                ICryptoTransform transform = symmKey.CreateDecryptor();

                // Создаем поток разшифрования из файла.
                using (CryptoStream cs = new CryptoStream(ifs, transform, CryptoStreamMode.Read))
                {
                    // Открываем расшифрованный файл
                    using (MemoryStream ofs = new MemoryStream(decData))
                    {
                        byte[] data = new byte[4096];
                        // и переписываем содержимое в выходной поток.
                        int length = cs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            ofs.Write(data, 0, length);
                            length = cs.Read(data, 0, data.Length);
                        }
                    }
                }
            }

            return decData;
        }

        /// <summary>
        /// Хэширование данных
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] data)
        {
            HashAlgorithm myhash = HashAlgorithm.Create("GOST3411");

            if (myhash == null)
                throw new NullReferenceException(nameof(myhash));

            byte[] hashValue = myhash.ComputeHash(data);

            return hashValue;
        }

        /// <summary>
        /// Хэширование файла
        /// </summary>
        /// <param name="filename"></param>
        /// <returns></returns>
        public byte[] ComputeFileHash(string filename)
        {
            if (!File.Exists(filename))
                return new byte[0];

            byte[] buffer = null;

            using (FileStream inStream = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                if (inStream.Length > int.MaxValue)
                {
                    throw new Exception("Файл слишком большой.");
                }

                buffer = new byte[inStream.Length];
                inStream.Read(buffer, 0, (int)inStream.Length);
            }

            byte[] hashValue = ComputeHash(buffer);

            return hashValue;
        }
    }
}
