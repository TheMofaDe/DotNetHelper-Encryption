using System;
using System.Security.Cryptography;
using System.Text;
using DotNetHelper_Contracts.Enum.Encryption;
using TheMoFaDe.Security;

namespace TheMoFaDe.Extensions.Security
{
    public static class StringExtensions
    {
        public static string SymmetricAlgorithmEncrypt(this string text, SymmetricAlgorithm symmetricAlgorithm, string password, Encoding encoding)
        {
            if (text.IsNotNull() && password.IsNotNull())
            {
                var keyFactory = new KeyFactory();

                return text.SymmetricAlgorithmEncrypt(symmetricAlgorithm, keyFactory.CreateKey(password, encoding));
            }
            else
                return null;
        }

        public static string SymmetricAlgorithmEncrypt(this string text, SymmetricAlgorithm symmetricAlgorithm, byte[] key, Encoding encoding)
        {
            if (text.IsNotNull())
            {
                var valueBytes = text.GetBytes(encoding);

                var result = valueBytes.SymmetricAlgorithmEncrypt(symmetricAlgorithm, key);

                if (result.IsNotNull())
                    return result.GetString();
            }

            return null;
        }

        public static string SymmetricAlgorithmDecrypt(this string text, SymmetricAlgorithm symmetricAlgorithm, string password, Encoding encoding)
        {
            if (text.IsNotNull() && password.IsNotNull())
            {
                var keyFactory = new KeyFactory();
                return text.SymmetricAlgorithmDecrypt(symmetricAlgorithm, keyFactory.CreateKey(password, encoding));
            }
            else
                return null;
        }

        public static string SymmetricAlgorithmDecrypt(this string text, SymmetricAlgorithm symmetricAlgorithm, byte[] key, Encoding encoding)
        {
            if (text.IsNotNull())
            {
                var valueBytes = text.GetBytes(encoding);

                var result = valueBytes.SymmetricAlgorithmDecrypt(symmetricAlgorithm, key);

                if (result.IsNotNull())
                    return result.GetString();
            }

            return null;
        }

        public static string AesEncrypt(this string text, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.AES);
            return text.SymmetricAlgorithmEncrypt(symmetricAlgorithm, keyFactory.CreateKey(16, password,encoding));
        }

        public static string AesDecrypt(this string text, string password, Encoding encoding)
        {
         
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.AES);
            return text.SymmetricAlgorithmDecrypt(symmetricAlgorithm, keyFactory.CreateKey(16, password, encoding));
        }

        public static string DesEncrypt(this string text, string password, Encoding encoding)
        {
         
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.DES);
            return text.SymmetricAlgorithmEncrypt(symmetricAlgorithm, keyFactory.CreateKey(8, password, encoding));
        }

        public static string DesDecrypt(this string text, string password, Encoding encoding)
        {
         
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.DES);
            return text.SymmetricAlgorithmDecrypt(symmetricAlgorithm, keyFactory.CreateKey(8, password, encoding));
        }

        public static string Rc2Encrypt(this string text, string password, Encoding encoding)
        {
         
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.RC2);
            return text.SymmetricAlgorithmEncrypt(symmetricAlgorithm, password, encoding);
        }

        public static string Rc2Decrypt(this string text, string password, Encoding encoding)
        {
         
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.RC2);
            return text.SymmetricAlgorithmDecrypt(symmetricAlgorithm, password, encoding);
        }

        public static string TripleDesEncrypt(this string text, string password, Encoding encoding)
        {
         
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.TripleDES);
            return text.SymmetricAlgorithmEncrypt(symmetricAlgorithm, password, encoding);
        }

        public static string TripleDesDecrypt(this string text, string password, Encoding encoding)
        {
         
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.TripleDES);
            return text.SymmetricAlgorithmDecrypt(symmetricAlgorithm, password, encoding);
        }

        public static string HashAlgorithmComputeHash(this string value, HashAlgorithm hashAlgorithm, Encoding encoding)
        {
            if (value.IsNotNull() == true)
            {
                var hash = hashAlgorithm.ComputeHash(value.GetBytes(encoding));
                var result = new StringBuilder();
                foreach (var t in hash)
                {
                    result.Append(t.ToString("X2"));
                }
                return result.ToString();
            }
            else
                return null;
        }

        public static bool HashAlgorithmVerifyHash(this string value, string hash, HashAlgorithm hashAlgorithm, Encoding encoding)
        {
            return StringComparer.OrdinalIgnoreCase.Compare(value.HashAlgorithmComputeHash(hashAlgorithm, encoding), hash) == 0;
        }

        public static string KeyedHashAlgorithmComputeHash(this string value, Encoding encoding)
        {
            return value.HashAlgorithmComputeHash(KeyedHashAlgorithm.Create(), encoding);
        }

        public static bool KeyedHashAlgorithmVerifyHash(this string value, string hash, Encoding encoding)
        {
            return value.HashAlgorithmVerifyHash(hash, KeyedHashAlgorithm.Create(), encoding);
        }

        public static string Md5ComputeHash(this string value, Encoding encoding)
        {
            return value.HashAlgorithmComputeHash(MD5.Create(), encoding);
        }

        public static bool Md5VerifyHash(this string value, string hash, Encoding encoding)
        {
            return value.HashAlgorithmVerifyHash(hash, MD5.Create(), encoding);
        }

        public static string Sha1ComputeHash(this string value, Encoding encoding)
        {
            return value.HashAlgorithmComputeHash(SHA1.Create(), encoding);
        }

        public static bool Sha1VerifyHash(this string value, string hash, Encoding encoding)
        {
            return value.HashAlgorithmVerifyHash(hash, SHA1.Create(), encoding);
        }

        public static string Sha256ComputeHash(this string value, Encoding encoding)
        {
            return value.HashAlgorithmComputeHash(SHA256.Create(), encoding);
        }

        public static bool Sha256VerifyHash(this string value, string hash, Encoding encoding)
        {
            return value.HashAlgorithmVerifyHash(hash, SHA256.Create(), encoding);
        }

        public static string Sha384ComputeHash(this string value, Encoding encoding)
        {
            return value.HashAlgorithmComputeHash(SHA384.Create(), encoding);
        }

        public static bool Sha384VerifyHash(this string value, string hash, Encoding encoding)
        {
            return value.HashAlgorithmVerifyHash(hash, SHA384.Create(),encoding);
        }

        public static string Sha512ComputeHash(this string value, Encoding encoding)
        {
            return value.HashAlgorithmComputeHash(SHA512.Create(), encoding);
        }

        public static bool Sha512VerifyHash(this string value, string hash, Encoding encoding)
        {
            return value.HashAlgorithmVerifyHash(hash, SHA512.Create(),encoding);
        }
    }
}
