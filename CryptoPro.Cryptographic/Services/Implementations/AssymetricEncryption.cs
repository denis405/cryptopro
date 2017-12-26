using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CryptoPro.Cryptographic.Services.Interfaces;
using CryptoPro.Helpers;
using CryptoPro.Helpers.Extensions;
using CryptoPro.Sharpei;

namespace CryptoPro.Cryptographic.Services.Implementations
{
    /// <summary>
    /// Ассиметричное шифрование
    /// </summary>
    public class AssymetricEncryptionService : IEncryptionService
    {
        private readonly ICertificateService _certificateService;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificateService"></param>
        public AssymetricEncryptionService(ICertificateService certificateService)
        {
            _certificateService = certificateService;
        }

        /// <summary>
        /// Зашифровать симметричный ключ
        /// </summary>
        /// <param name="symmKey"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        public byte[] EncryptSymmKey(Gost28147 symmKey, string recipientName)
        {
            Log.DssLogger.Debug($"Шифрование симметричного ключа на получателя {recipientName}");

            byte[] returnArray;

            try
            {
                X509Certificate2 cert = _certificateService.FindAddressBookCertificateBySubjectName(recipientName)
                    .Result;

                // Если ничего не нашли - выходим
                if (cert == null)
                {
                    return null;
                }

                // Открытый ключ получателя.
                AsymmetricAlgorithm pk = cert.PublicKey.Key;
                Gost3410 recipient = pk as Gost3410;
                if (recipient == null)
                    throw new CryptographicException("Not a gost certificate");

                GostKeyExchangeFormatter keyFormatter = new GostKeyExchangeFormatter(recipient);

                byte[] transport = keyFormatter.CreateKeyExchangeData(symmKey);

                // Создаем зашифрованный файл.
                using (MemoryStream ms = new MemoryStream())
                {
                    // Записываем зашифрованный симметричный ключ в виде транспортного представления.
                    BinaryWriter bw = new BinaryWriter(ms);
                    bw.Write(transport.Length);
                    bw.Write(transport);

                    // Записываем синхропосылку
                    bw.Write(symmKey.IV.Length);
                    bw.Write(symmKey.IV);

                    returnArray = ms.ToArray();
                }
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при зашифровании симметричного ключа: {exp}");
                returnArray = null;
            }

            return returnArray;
        }

        /// <summary>
        /// Расшифровать симметричный ключ
        /// </summary>
        /// <param name="symmKey"></param>
        /// <param name="recipientContainer"></param>
        /// <param name="isMachine"></param>
        /// <returns></returns>
        public SymmetricAlgorithm DecryptSymmKey(byte[] symmKey, string recipientContainer, bool isMachine)
        {
            Log.DssLogger.Debug($"Расшифрование симметричного ключа по ключу в контейнере {recipientContainer}");

            SymmetricAlgorithm symmetric;

            try
            {
                // Открываем ключ получателя.
                CspParameters par = new CspParameters(75, null, recipientContainer);
                if (isMachine)
                {
                    par.Flags = CspProviderFlags.UseMachineKeyStore;
                }

                Gost3410CryptoServiceProvider destContainer2 = new Gost3410CryptoServiceProvider(par);

                // Создаем deformater для транспортного ключа.
                GostKeyExchangeDeformatter keyDeformater2 = new GostKeyExchangeDeformatter(destContainer2);

                // Открываем зашифрованный файл.
                using (MemoryStream ms = new MemoryStream(symmKey))
                {
                    // Читаем зашифрованный симметричный ключ.
                    BinaryReader br = new BinaryReader(ms);
                    int transportLength = br.ReadInt32();
                    byte[] transport = br.ReadBytes(transportLength);

                    symmetric = keyDeformater2.DecryptKeyExchangeData(transport);

                    // Читаем синхропосылку
                    byte[] iv;
                    int ivLength = br.ReadInt32();
                    iv = br.ReadBytes(ivLength);
                    symmetric.IV = iv;
                }
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при расшифровании симметричного ключа: {exp}");
                symmetric = null;
            }

            return symmetric;
        }

        /// <summary>
        /// Зашифровать строку
        /// </summary>
        /// <param name="data"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        public byte[] EncryptData(string data, string recipientName)
        {
            Log.DssLogger.Debug($"Зашифровка строки на получателя {recipientName}");

            byte[] envelopedbytes = null;

            try
            {
                X509Certificate2 recipientCertificate = _certificateService.FindAddressBookCertificateBySubjectName(recipientName).Result;

                // Если ничего не нашли - выходим
                if (recipientCertificate == null)
                {
                    return null;
                }

                byte[] dataToEncrypt = Encoding.UTF8.GetBytes(data);

                ContentInfo content = new ContentInfo(dataToEncrypt);
                EnvelopedCms envelopedCms = new EnvelopedCms(content);
                CmsRecipient recip1 = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCertificate);
                envelopedCms.Encrypt(recip1);

                envelopedbytes = envelopedCms.Encode();
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при зашифровании строки: {exp}");
                envelopedbytes = null;
            }

            return envelopedbytes;
        }

        /// <summary>
        /// Зашифровать массив строк
        /// </summary>
        /// <param name="data"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        public byte[] EncryptData(string[] data, string recipientName)
        {
            byte[] envelopedbytes = null;

            try
            {
                X509Certificate2 recipientCertificate = _certificateService.FindAddressBookCertificateBySubjectName(recipientName).Result;

                // Если ничего не нашли - выходим
                if (recipientCertificate == null)
                {
                    return null;
                }

                byte[] dataToEncrypt = data.ToList().ListToBytes();

                ContentInfo content = new ContentInfo(dataToEncrypt);
                EnvelopedCms envelopedCms = new EnvelopedCms(content);
                CmsRecipient recip1 = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCertificate);
                envelopedCms.Encrypt(recip1);

                envelopedbytes = envelopedCms.Encode();
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при зашифровании строки: {exp}");
                envelopedbytes = null;
            }

            return envelopedbytes;
        }

        /// <summary>
        /// Зашифровать массив байт
        /// </summary>
        /// <param name="data"></param>
        /// <param name="recipientName"></param>
        /// <returns></returns>
        public byte[] EncryptData(byte[] data, string recipientName)
        {
            byte[] envelopedbytes = null;

            try
            {
                X509Certificate2 recipientCertificate = _certificateService.FindAddressBookCertificateBySubjectName(recipientName).Result;

                // Если ничего не нашли - выходим
                if (recipientCertificate == null)
                {
                    return null;
                }

                ContentInfo content = new ContentInfo(data);
                EnvelopedCms envelopedCms = new EnvelopedCms(content);
                CmsRecipient recip1 = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCertificate);
                envelopedCms.Encrypt(recip1);

                envelopedbytes = envelopedCms.Encode();
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при зашифровании строки: {exp}");
                envelopedbytes = null;
            }

            return envelopedbytes;
        }

        /// <summary>
        /// Расшифровать данные
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string DecryptString(byte[] data)
        {
            string result = null;

            try
            {
                EnvelopedCms envelopedCms = new EnvelopedCms();

                envelopedCms.Decode(data);
                envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);

                byte[] byteResult = envelopedCms.ContentInfo.Content;
                result = Encoding.UTF8.GetString(byteResult);
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при зашифровании строки: {exp}");
                result = null;
            }

            return result;
        }

        /// <summary>
        /// Расшифровать массив данных
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string[] DecryptStringArray(byte[] data)
        {
            string[] result = null;

            try
            {
                EnvelopedCms envelopedCms = new EnvelopedCms();

                envelopedCms.Decode(data);
                envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);

                byte[] byteResult = envelopedCms.ContentInfo.Content;
                result = new List<string>(byteResult.BytesToList<string>()).ToArray();
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при зашифровании строки: {exp}");
                result = null;
            }

            return result;
        }

        /// <summary>
        /// Расшифровать данные и получить массив байт
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] DecryptByteArray(byte[] data)
        {
            byte[] byteResult = null;

            try
            {
                EnvelopedCms envelopedCms = new EnvelopedCms();

                envelopedCms.Decode(data);
                envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);

                byteResult = envelopedCms.ContentInfo.Content;
            }
            catch (Exception exp)
            {
                Log.DssLogger.Error($"Ошибка при зашифровании строки: {exp}");
                byteResult = null;
            }

            return byteResult;
        }
    }
}
