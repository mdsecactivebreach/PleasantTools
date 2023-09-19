using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace PleasantDecrypter
{
    class EncryptionHelper
    {
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        private static Aes CreateAes()
        {
            Aes aes;
            try
            {
                aes = Aes.Create();
            }
            catch
            {
                aes = new AesCryptoServiceProvider();
            }
            return aes;
        }
        public static byte[] DecryptToBytes(string key, byte[] data)
        {
            byte[] salt = new byte[8];
            Array.Copy(data, salt, salt.Length);
            byte[] dataNoSalt = new byte[data.Length - salt.Length];
            Array.Copy(data, salt.Length, dataNoSalt, 0, data.Length - salt.Length);
            byte[] array;
            using (Aes aes = CreateAes())
            {
                try
                {
                    aes.KeySize = 256;
                    Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(key, salt);
                    aes.Key = rfc2898.GetBytes(aes.KeySize / 8);
                    aes.IV = rfc2898.GetBytes(aes.BlockSize / 8);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(dataNoSalt, 0, dataNoSalt.Length);
                        }
                        array = ms.ToArray();
                    }
                }
                catch (CryptographicException)
                {
                    array = null;
                }
            }
            return array;
        }
        public static string DecryptToString(string key, byte[] data)
        {
            byte[] decryptedBytes = DecryptToBytes(key, data);
            if (decryptedBytes == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
