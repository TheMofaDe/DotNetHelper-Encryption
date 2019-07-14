# DotNetHelper.Encryption

#### *DotNetHelper-Encryption is a .net library that is wraps the System.Security.Cryptography to easily interchangable hashing & encryption.* 

|| [**View on Github**][Github] || 


## Hashing Support
+ CRC32
+ SHA1
+ SHA256
+ SHA384
+ SHA512
+ MD5

## Encryption Support
+ DES
+ RC2
+ Rijndael
+ TripleDES
+ AES


## How to use
##### HASHING
```csharp
using DotNetHelper_Encryption
  class Program
    {
        static void Main(string[] args)
        {
            var passwordAsBytes = Encoding.UTF8.GetBytes("password");
            var hashProvider = HashProvider.SHA256;// an enum with the options of CRC32,SHA1,SHA256,SHA384,SHA512,MD5
            var hashAlgorithm = HashingFactory.Create(hashProvider); 
            var hashValue = hashAlgorithm.ComputeHash(new MemoryStream(passwordAsBytes));
        }
    }
```

##### ENCRYPTION & DECRYPTION
```csharp
using DotNetHelper_Encryption
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
            }
            
            string passwordButDecrypted;
            passwordStream.Seek(0, SeekOrigin.Begin);
            using (var decryptorStream = new CryptoStream(passwordStream, symmetricAlgorithm.CreateDecryptor(), CryptoStreamMode.Read))
            {
                  passwordButDecrypted = new StreamReader(decryptorStream).ReadToEnd();
            }

        }
    }
```


<!-- Links. -->

[1]:  https://gist.github.com/davidfowl/ed7564297c61fe9ab814
[2]: http://themofade.github.io/DotNetHelper-Encryption

[Cake]: https://gist.github.com/davidfowl/ed7564297c61fe9ab814
[Azure DevOps]: https://gist.github.com/davidfowl/ed7564297c61fe9ab814
[AppVeyor]: https://gist.github.com/davidfowl/ed7564297c61fe9ab814
[GitVersion]: https://gitversion.readthedocs.io/en/latest/
[Nuget]: https://gist.github.com/davidfowl/ed7564297c61fe9ab814
[Chocolately]: https://gist.github.com/davidfowl/ed7564297c61fe9ab814
[WiX]: http://wixtoolset.org/
[DocFx]: https://dotnet.github.io/docfx/
[Github]: https://github.com/TheMofaDe/DotNetHelper-Encryption


<!-- Documentation Links. -->
[Docs]: https://themofade.github.io/DotNetHelper-Encryption/index.html
[Docs-API]: https://themofade.github.io/DotNetHelper-Encryption/api/DotNetHelper-Encryption.Attribute.html
[Docs-Tutorials]: https://themofade.github.io/DotNetHelper-Encryption/tutorials/index.html
[Docs-samples]: https://dotnet.github.io/docfx/
[Changelogs]: https://dotnet.github.io/docfx/