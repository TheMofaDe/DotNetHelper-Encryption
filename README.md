# DotNetHelper-Encryption

#### *DotNetHelper-Encryption is a .net library that is wraps the System.Security.Cryptography to easily interchangable hashing & encryption.* 

|| [**Documentation**][Docs] • [**API**][Docs-API] • [**Tutorials**][Docs-Tutorials] ||  [**Change Log**][Changelogs] • || [**View on Github**][Github]|| 

| AppVeyor | AzureDevOps |
| :-----: | :-----: |
| [![Build status](https://ci.appveyor.com/api/projects/status/kok7biys3w41foph?svg=true)](https://ci.appveyor.com/project/TheMofaDe/dotnethelper-encryption)  | [![Build Status](https://dev.azure.com/Josephmcnealjr0013/DotNetHelper-Encryption/_apis/build/status/TheMofaDe.DotNetHelper-Encryption?branchName=master)](https://dev.azure.com/Josephmcnealjr0013/DotNetHelper-Encryption/_build/latest?definitionId=5&branchName=master)  

| Package  | Tests | Code Coverage |
| :-----:  | :---: | :------: |
| ![Build Status][nuget-downloads]  | ![Build Status][tests]  | [![codecov](https://codecov.io/gh/TheMofaDe/DotNetHelper-Encryption/branch/master/graph/badge.svg)](https://codecov.io/gh/TheMofaDe/DotNetHelper-Encryption) |



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


## Documentation
For more information, please refer to the [Officials Docs][Docs]

Created Using [DotNet-Starter-Template](http://themofade.github.io/DotNet-Starter-Template) 


<!-- Links. -->

[1]:  https://gist.github.com/davidfowl/ed7564297c61fe9ab814


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
[Docs-API]: https://themofade.github.io/DotNetHelper-Encryption/api/DotNetHelper-Encryption.html
[Docs-Tutorials]: https://themofade.github.io/DotNetHelper-Encryption/tutorials/index.html
[Docs-samples]: https://dotnet.github.io/docfx/
[Changelogs]: https://dotnet.github.io/docfx/


<!-- BADGES. -->

[nuget-downloads]: https://img.shields.io/nuget/dt/DotNetHelper-Encryption.svg?style=flat-square
[tests]: https://img.shields.io/appveyor/tests/themofade/DotNetHelper-Encryption.svg?style=flat-square
[coverage-status]: https://dev.azure.com/Josephmcnealjr0013/DotNetHelper-Encryption/_apis/build/status/TheMofaDe.DotNetHelper-Encryption?branchName=master&jobName=Windows
