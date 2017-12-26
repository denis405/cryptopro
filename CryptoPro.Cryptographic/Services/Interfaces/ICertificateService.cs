using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CryptoPro.Cryptographic.Services.Interfaces
{
    /// <summary>
    /// Интерфейс сервиса работы с сертификатами
    /// </summary>
    public interface ICertificateService
    {
        /// <summary>
        /// Добаление контейнера закрытого ключа
        /// </summary>
        /// <param name="containerName"></param>
        /// <returns></returns>
        Task<bool> AddContainer(string containerName);

        /// <summary>
        /// Добавление сертификата в контейнер с закрытым ключом
        /// </summary>
        /// <param name="certName"></param>
        /// <param name="containerName"></param>
        /// <returns></returns>
        Task<bool> AddCertificate(string certName, string containerName);

        /// <summary>
        /// Добавить сертификат в хранилище из контейнера
        /// </summary>
        /// <param name="containerName"></param>
        /// <param name="isMachine"></param>
        /// <returns></returns>
        Task<bool> AddCertificateToStore(string containerName, bool isMachine);

        /// <summary>
        /// Найти сертификат получателя в хранилище AddressBook
        /// </summary>
        /// <param name="subjectName"></param>
        /// <returns></returns>
        Task<X509Certificate2> FindAddressBookCertificateBySubjectName(string subjectName);
    }
}
