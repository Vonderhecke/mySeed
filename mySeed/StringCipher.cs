
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace mySeed
{
    public static class StringCipher
    {
        //private static byte[] gIV = new byte[16];

        public static string EncryptString(string original, string password)
        {
            if (original == "") return "";
            using Aes myAes = Aes.Create();
            byte[] bPassword = ASCIIEncoding.ASCII.GetBytes(password);
            byte[] hashPassword = MD5.HashData(bPassword);
            byte[] encrypted = EncryptStringToBytes_Aes(original, hashPassword, myAes.IV);

            return BitConverter.ToString(encrypted).Replace("-", "");
        }

        public static string DecryptString(string encrypted, string password) 
        {
            if (encrypted == "") return "";
            //using Aes myAes = Aes.Create();
            byte[] bPassword = ASCIIEncoding.ASCII.GetBytes(password);
            byte[] hashPassword = MD5.HashData(bPassword);
            try
            {
                byte[] encryptedByteArray = Enumerable.Range(0, encrypted.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(encrypted.Substring(x, 2), 16))
                    .ToArray();
                return DecryptStringFromBytes_Aes(encryptedByteArray, hashPassword);// myAes.IV);
            }
            catch { }
            return "";

        }


        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException(nameof(plainText));
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException(nameof(Key));
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException(nameof(IV));
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using MemoryStream msEncrypt = new();
                using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
                using (StreamWriter swEncrypt = new(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
                encrypted = msEncrypt.ToArray();
            }

            byte[] all = new byte[IV.Length + encrypted.Length + 1];
            all[0] = (byte)IV.Length;
            Array.Copy(IV, 0, all, 1, IV.Length);
            Array.Copy(encrypted, 0, all, IV.Length + 1, encrypted.Length);
            return all;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException(nameof(Key));

            byte[] IV = new byte[cipherText[0]];
            Array.Copy(cipherText, 1, IV, 0, cipherText[0]);
            byte[] encrypted = new byte[cipherText.Length - cipherText[0] - 1];
            Array.Copy(cipherText, 1 + cipherText[0], encrypted, 0, encrypted.Length);


            // Declare the string used to hold
            // the decrypted text.
            string? plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using MemoryStream msDecrypt = new(encrypted);
                using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
                using StreamReader srDecrypt = new(csDecrypt);
                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }
    }
}

