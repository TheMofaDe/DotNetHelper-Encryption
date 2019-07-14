using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using DotNetHelper_Encryption;
using DotNetHelper_Encryption.Enums;
using DotNetHelper_Encryption.Helper;

namespace SampleConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {

            var password = "password";
            string encryptedPassword;
            var symmetricProvider = SymmetricProvider.AES; // an enum with the options of AES,DES,RC2,Rijndael,TripleDES
            var symmetricAlgorithm = SymmetricFactory.Create(symmetricProvider);
            
            using (symmetricAlgorithm)
            {
                var passwordStream = new MemoryStream();
                var cryptoStream = new CryptoStream(passwordStream, symmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Write);
                new MemoryStream(Encoding.UTF8.GetBytes(password)).CopyTo(cryptoStream);
                cryptoStream.FlushFinalBlock();
                passwordStream.Seek(0, SeekOrigin.Begin);
                encryptedPassword = new StreamReader(passwordStream).ReadToEnd();


                string passwordButDecrypted;
                passwordStream.Seek(0, SeekOrigin.Begin);
                using (var decryptorStream = new CryptoStream(passwordStream, symmetricAlgorithm.CreateDecryptor(), CryptoStreamMode.Read))
                {
                   passwordButDecrypted = new StreamReader(decryptorStream).ReadToEnd();
                }
            }

            //var passwordAsBytes = Encoding.UTF8.GetBytes("password");
            //var hashAlgorithm = HashingFactory.Create(HashProvider.SHA256);
            //var hashValue = hashAlgorithm.ComputeHash(new MemoryStream(passwordAsBytes));
            //var b = SHA256.Create().ComputeHash(new MemoryStream(passwordAsBytes));
            //var c = SHA256Managed.Create().ComputeHash(new MemoryStream(passwordAsBytes));
            //var d = SHA256Cng.Create().ComputeHash(new MemoryStream(passwordAsBytes));
            //var e = SHA256CryptoServiceProvider.Create().ComputeHash(new MemoryStream(passwordAsBytes));

            //var a2 = Encoding.UTF8.GetString(a);
            //var b2 = Encoding.UTF8.GetString(b);
            //var c2 = Encoding.UTF8.GetString(c);
            //var d2 = Encoding.UTF8.GetString(d);
            //var e2 = Encoding.UTF8.GetString(e);


            //Console.WriteLine(a2);
            //Console.WriteLine(b2);
            //Console.WriteLine(c2);
            //Console.WriteLine(d2);
            //Console.WriteLine(e2);


            //var hashValueAsBytes = hashAlgorithm.ComputeHash(passwordAsStream);
            // var hashValueAsString = Encoding.UTF8.GetString(hashValueAsBytes);
            // Console.WriteLine(hashValueAsString);
        }
    }
}
