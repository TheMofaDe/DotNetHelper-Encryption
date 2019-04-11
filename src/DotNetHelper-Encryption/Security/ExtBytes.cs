using DotNetHelper_Contracts.Enum.Encryption;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using TheMoFaDe.Security;

namespace TheMoFaDe.Extensions.Security
{
    public class KeyFactory
    {
        public byte[] CreateKey(int length, string seed, Encoding encoding)
        {
            return seed.IsNotNull() ? seed.GetBytes(encoding).Md5ComputeHash().Take(length).ToArray() : null;
        }

        public byte[] CreateKey(string seed, Encoding encoding)
        {
            return seed.IsNotNull() ? seed.GetBytes(encoding).Md5ComputeHash() : null;
        }
    }

    // TODO :: THEMOFADE VITAL IMPORTANT !!!!! MAKE SURE YOU WRAP THIS STUFF IN USING STATEMENT GEEZ 
    public static class ByteExtensions
    {
        public static byte[] ComputeHash(this byte[] value, HashAlgorithm hashAlgorithm)
        {
            if (value.IsNotNull() == true)
            {
                return hashAlgorithm.ComputeHash(value);
            }
            else
                return null;
        }

        public static bool VerifyHash(this byte[] value, byte[] hash, HashAlgorithm hashAlgorithm)
        {
            var hashToCompare = value.ComputeHash(hashAlgorithm);

            if (hash == null || hashToCompare == null)
            {
                return false;
            }

            if (hash.Length != hashToCompare.Length)
            {
                return false;
            }

            return !hash.Where((t, i) => t != hashToCompare[i]).Any();
        }

        public static byte[] Md5ComputeHash(this byte[] value)
        {
            return value.ComputeHash(MD5.Create());
        }

        public static bool Md5VerifyHash(this byte[] value, byte[] hash)
        {
            return value.VerifyHash(hash, MD5.Create());
        }

        public static byte[] SymmetricAlgorithmEncrypt(this byte[] value, SymmetricAlgorithm symmetricAlgorithm, byte[] key)
        {
            if (value.IsNotNull() && key.IsNotNull())
            {
                symmetricAlgorithm.Key = key;

                var cryptoTransform = symmetricAlgorithm.CreateEncryptor();
                var result = cryptoTransform.TransformFinalBlock(value, 0, value.Length);
                symmetricAlgorithm.Clear();

                return result;
            }
            else
                return null;
        }

        public static byte[] SymmetricAlgorithmDecrypt(this byte[] value, SymmetricAlgorithm symmetricAlgorithm, byte[] key)
        {
            if (value.IsNotNull() && key.IsNotNull())
            {
                symmetricAlgorithm.Key = key;

                var cryptoTransform = symmetricAlgorithm.CreateDecryptor();
                var result = cryptoTransform.TransformFinalBlock(value, 0, value.Length);
                symmetricAlgorithm.Clear();

                return result;
            }
            else
                return null;
        }

        public static byte[] AesEncrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            using (var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.AES))
            {
                return data.SymmetricAlgorithmEncrypt(symmetricAlgorithm, keyFactory.CreateKey(16, password, encoding));
            }
        }

        public static byte[] AesDecrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.AES);
            return data.SymmetricAlgorithmDecrypt(symmetricAlgorithm, keyFactory.CreateKey(16, password, encoding));
        }

        public static byte[] DesEncrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.DES);
            return data.SymmetricAlgorithmEncrypt(symmetricAlgorithm, keyFactory.CreateKey(8, password, encoding));
        }

        public static byte[] DesDecrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.DES);
            return data.SymmetricAlgorithmDecrypt(symmetricAlgorithm, keyFactory.CreateKey(8, password, encoding));
        }

        public static byte[] Rc2Encrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.RC2);
            return data.SymmetricAlgorithmEncrypt(symmetricAlgorithm, keyFactory.CreateKey(password, encoding));
        }

        public static byte[] Rc2Decrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.RC2);
            return data.SymmetricAlgorithmDecrypt(symmetricAlgorithm, keyFactory.CreateKey(password, encoding));
        }

        public static byte[] TripleDesEncrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.TripleDES);
            return data.SymmetricAlgorithmEncrypt(symmetricAlgorithm, keyFactory.CreateKey(password, encoding));
        }

        public static byte[] TripleDesDecrypt(this byte[] data, string password, Encoding encoding)
        {
          
            var keyFactory = new KeyFactory();
            var symmetricAlgorithm = EncryptionSymmetric.Create(SymmetricProvider.TripleDES);
            return data.SymmetricAlgorithmDecrypt(symmetricAlgorithm, keyFactory.CreateKey(password, encoding));
        }
    }
}
