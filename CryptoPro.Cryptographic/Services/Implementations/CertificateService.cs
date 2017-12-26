using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CryptoPro.Cryptographic.Services.Interfaces;
using CryptoPro.Helpers.Helpers;
using CryptoPro.Sharpei;

namespace CryptoPro.Cryptographic.Services.Implementations
{
    /// <summary>
    /// Сервис работы с сертификатами
    /// </summary>
    public class CertificateService : ICertificateService
    {
        /// <summary>
        /// Добаление контейнера закрытого ключа
        /// </summary>
        /// <param name="containerName"></param>
        /// <returns></returns>
        public Task<bool> AddContainer(string containerName)
        {
            // Открываем контейнер
            CspParameters cspParameters = new CspParameters(75) { KeyContainerName = containerName };
            Gost3410CryptoServiceProvider prov = new Gost3410CryptoServiceProvider(cspParameters);

            // Освобождаем ресурсы занятые провайдером.
            prov.Clear();

            return Task.FromResult(true);
        }

        /// <summary>
        /// Добавление сертификата в контейнер с закрытым ключом
        /// </summary>
        /// <param name="certName"></param>
        /// <param name="containerName"></param>
        /// <returns></returns>
        public Task<bool> AddCertificate(string certName, string containerName)
        {
            // Открываем контейнер
            CspParameters cspParameters = new CspParameters(75) { KeyContainerName = containerName };
            Gost3410CryptoServiceProvider prov = new Gost3410CryptoServiceProvider(cspParameters);

            // Достаем из него сертификат
            X509Certificate2 cert = new X509Certificate2(certName);

            prov.ContainerCertificate = cert;

            // Освобождаем ресурсы занятые провайдером.
            prov.Clear();

            return Task.FromResult(true);
        }

        /// <summary>
        /// Добавить сертификат в хранилище из контейнера
        /// </summary>
        /// <param name="containerName"></param>
        /// <param name="isMachine"></param>
        /// <returns></returns>
        public Task<bool> AddCertificateToStore(string containerName, bool isMachine)
        {
            // Открываем контейнер.
            CspParameters cspParameters = new CspParameters(75) { KeyContainerName = containerName };
            Gost3410CryptoServiceProvider prov = new Gost3410CryptoServiceProvider(cspParameters);

            // Достаем из него сертификат
            X509Certificate2 cert = prov.ContainerCertificate;

            if (cert == null)
            {
                return Task.FromResult(false);
            }

            // Открываем хранилище MY текущего пользователя. 
            X509Store myStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            myStore.Open(OpenFlags.ReadWrite);

            // Добавляем в него сертификат.
            cert.PrivateKey = prov;
            myStore.Add(cert);

            // Закрываем хранилище.
            myStore.Close();
            // Освобождаем ресурсы занятые провайдером.
            prov.Clear();

            return Task.FromResult(true);
        }

        /// <summary>
        /// Найти сертификат получателя в хранилище AddressBook
        /// </summary>
        /// <param name="subjectName"></param>
        /// <returns></returns>
        public Task<X509Certificate2> FindAddressBookCertificateBySubjectName(string subjectName)
        {
            X509Store store = new X509Store(StoreName.AddressBook, CurrentInfo.IsMachine() ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2 recipientCertificate = null;

            // Перебираем сертификаты и ищем по имени
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                if (certificate.SubjectName.Name != null)
                {
                    if (certificate.SubjectName.Name.Contains(subjectName))
                    {
                        recipientCertificate = certificate;
                        break;
                    }
                }
            }

            store.Close();

            if (recipientCertificate == null)
                throw new Exception($"Сертификат по наименованию {subjectName} в хранилище не найден");

            return Task.FromResult(recipientCertificate);
        }
    }
}
