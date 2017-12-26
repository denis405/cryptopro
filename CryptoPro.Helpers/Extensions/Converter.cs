using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace CryptoPro.Helpers.Extensions
{
    /// <summary>
    /// Расширение конвертера
    /// </summary>
    public static class Converter
    {
        /// <summary>
        /// Bytes to List
        /// </summary>
        /// <param name="list"></param>
        /// <returns></returns>
        public static byte[] ListToBytes(this IList list)
        {
            byte[] buffer;

            BinaryFormatter bf = new BinaryFormatter();

            using (MemoryStream s = new MemoryStream())
            {
                bf.Serialize(s, list);
                buffer = s.ToArray();
            }

            return buffer;
        }

        /// <summary>
        /// List to Bytes
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static IList<T> BytesToList<T>(this byte[] bytes)
        {
            List<T> result;

            BinaryFormatter bf = new BinaryFormatter();

            using (Stream ms = new MemoryStream(bytes))
            {
                result = (List<T>)bf.Deserialize(ms);
            }

            return result;
        }

        /// <summary>
        /// Convert an object to a byte array
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static byte[] ObjectToByteArray<T>(T obj)
        {
            BinaryFormatter bf = new BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, obj);

            return ms.ToArray();
        }

        /// <summary>
        /// Convert a byte array to an Object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="arrBytes"></param>
        /// <returns></returns>
        public static T ByteArrayToObject<T>(byte[] arrBytes)
        {
            MemoryStream memStream = new MemoryStream();
            BinaryFormatter binForm = new BinaryFormatter();
            memStream.Write(arrBytes, 0, arrBytes.Length);
            memStream.Seek(0, SeekOrigin.Begin);
            T obj = (T)binForm.Deserialize(memStream);

            return obj;
        }

        /// <summary>
        /// Строка base64 в байты
        /// </summary>
        /// <param name="base64"></param>
        /// <returns></returns>
        public static byte[] ToLicenseBytes(this string base64)
        {
            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Байты в строку base64
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string ToBase64String(this byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Bytes to Hex string
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string ToHexString(this byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
