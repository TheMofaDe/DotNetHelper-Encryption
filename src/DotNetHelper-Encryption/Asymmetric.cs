﻿// A simple, string-oriented wrapper class for encryption functions, including 
// Hashing, Symmetric Encryption, and Asymmetric Encryption.
//
//  CREDIT Jeff Atwood
//   http://www.codinghorror.com/
//   http://www.codeproject.com/KB/security/SimpleEncryption.aspx

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace DotNetHelper_Encryption
{
    // Asymmetric encryption uses a pair of keys to encrypt and decrypt.
    // There is a "public" key which is used to encrypt. Decrypting, on the other hand, 
    // requires both the "public" key and an additional "private" key. The advantage is 
    // that people can send you encrypted messages without being able to decrypt them.

    /// <summary>
    /// Represents an object that performs asymmetric encryption.
    /// </summary>
    /// <remarks>The only provider supported is the RSACryptoServiceProvider.</remarks>
    public class EncryptionAsymmetric
    {
        private readonly RSACryptoServiceProvider _rsa;
        //private string _KeyContainerName = "Encryption.AsymmetricEncryption.DefaultContainerName";
        private readonly int _keySize = 1024;

        /// <summary>
        /// Initializes a new instance of the Asymmetric class using the default key size.
        /// </summary>
        public EncryptionAsymmetric()
        {
            _rsa = GetRsaProvider();
        }

        /// <summary>
        /// Initializes a new instance of the Asymmetric class using the specified key size.
        /// </summary>
        public EncryptionAsymmetric(int keySize)
        {
            _keySize = keySize;
            _rsa = GetRsaProvider();
        }

        /// <summary>
        /// Gets or sets the name of the key container used to store this key on disk. 
        /// </summary>
        /// <remarks>
        /// This is an unavoidable side effect of the underlying Microsoft CryptoAPI.
        /// http://support.microsoft.com/default.aspx?scid=http://support.microsoft.com:80/support/kb/articles/q322/3/71.asp&amp;NoWebContent=1
        /// </remarks>
        public string KeyContainerName { get; set; } = "Encryption.AsymmetricEncryption." + Guid.NewGuid();

        /// <summary>
        /// Gets the current key size, in bits.
        /// </summary>
        public int KeySizeBits => _rsa.KeySize;

        /// <summary>
        /// Gets the maximum supported key size, in bits.
        /// </summary>
        public int KeySizeMaxBits => _rsa.LegalKeySizes[0].MaxSize;

        /// <summary>
        /// Gets the minimum supported key size, in bits.
        /// </summary>
        public int KeySizeMinBits => _rsa.LegalKeySizes[0].MinSize;

        /// <summary>
        /// Gets the valid key step sizes, in bits.
        /// </summary>
        public int KeySizeStepBits => _rsa.LegalKeySizes[0].SkipSize;




        /// <summary>
        /// Generates a new public/private key pair as objects.
        /// </summary>
        public static KeyValuePair<PublicKey, PrivateKey> GenerateNewKeyset()
        {
            var xmlKeyset = GenerateNewXmlKeyset();
            return new KeyValuePair<PublicKey, PrivateKey>(new PublicKey(xmlKeyset.Key), new PrivateKey(xmlKeyset.Value));
        }

        /// <summary>
        /// Generates a new public/private key pair as XML strings.
        /// </summary>
        public static KeyValuePair<string, string> GenerateNewXmlKeyset()
        {
            using (var rsa = RSA.Create())
            {
                return new KeyValuePair<string, string>(rsa.ToXmlString(false), rsa.ToXmlString(true));
            }
        }



        /// <summary>
        /// Encrypts data using the provided public key.
        /// </summary>
        /// <exception cref="T:System.ArgumentNullException">data or publicKey is null.</exception>
        public Hash.PreEncryptData Encrypt(Hash.PreEncryptData data, PublicKey publicKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));

            _rsa.ImportParameters(publicKey.ToParameters());
            return EncryptPrivate(data);
        }

        /// <summary>
        /// Encrypts data using the provided public key XML.
        /// </summary>
        /// <exception cref="T:System.ArgumentNullException">data or publicKeyXml is null.</exception>
        public Hash.PreEncryptData Encrypt(Hash.PreEncryptData data, string publicKeyXml)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (publicKeyXml == null) throw new ArgumentNullException(nameof(publicKeyXml));

            LoadKeyXml(publicKeyXml, false);
            return EncryptPrivate(data);
        }

        private Hash.PreEncryptData EncryptPrivate(Hash.PreEncryptData data)
        {
            Debug.Assert(data != null);

            try
            {
                return new Hash.PreEncryptData(_rsa.Encrypt(data.Bytes, false));
            }
            catch (CryptographicException ex)
            {
                if (ex.Message.IndexOf("bad length", StringComparison.InvariantCultureIgnoreCase) > -1)
                {
                    throw new CryptographicException("Your data is too large; RSA encryption is designed to encrypt relatively small amounts of data. The exact byte limit depends on the key size. To encrypt more data, use symmetric encryption and then encrypt that symmetric key with asymmetric RSA encryption.", ex);
                }
                throw;
            }
        }


        /// <summary>
        /// Decrypts data using the provided private key.
        /// </summary>
        /// <exception cref="T:System.ArgumentNullException">data or privateKey is null.</exception>
        public Hash.PreEncryptData Decrypt(Hash.PreEncryptData data, PrivateKey privateKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));

            _rsa.ImportParameters(privateKey.ToParameters());
            return DecryptPrivate(data);
        }

        /// <summary>
        /// Decrypts data using the provided private key XML.
        /// </summary>
        /// <exception cref="T:System.ArgumentNullException">data or privateKeyXml is null.</exception>
        public Hash.PreEncryptData Decrypt(Hash.PreEncryptData data, string privateKeyXml)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (privateKeyXml == null) throw new ArgumentNullException(nameof(privateKeyXml));

            LoadKeyXml(privateKeyXml, true);
            return DecryptPrivate(data);
        }

        private void LoadKeyXml(string xmlString, bool isPrivate)
        {
            Debug.Assert(xmlString != null);

            try
            {
                _rsa.FromXmlString(xmlString);
            }
            catch (Exception ex)
            {
                var s = isPrivate ? "private" : "public";
                throw new Exception(string.Format(CultureInfo.CurrentCulture, "The provided {0} encryption key XML does not appear to be valid.", s), ex);
            }
        }

        private Hash.PreEncryptData DecryptPrivate(Hash.PreEncryptData data)
        {
            Debug.Assert(data != null);
            return new Hash.PreEncryptData(_rsa.Decrypt(data.Bytes, false));
        }

        /// <summary>
        /// Returns the default RSA provider using the specified key size.
        /// </summary>
        /// <remarks>
        /// Note that Microsoft's CryptoAPI has an underlying file system dependency that is unavoidable.
        /// http://support.microsoft.com/default.aspx?scid=http://support.microsoft.com:80/support/kb/articles/q322/3/71.asp&amp;NoWebContent=1
        /// </remarks>
        private RSACryptoServiceProvider GetRsaProvider()
        {
            try
            {
                var csp = new CspParameters {KeyContainerName = KeyContainerName};

                RSACryptoServiceProvider rsa = null;
                try
                {
                    rsa = new RSACryptoServiceProvider(_keySize, csp) {PersistKeyInCsp = false};

                    RSACryptoServiceProvider.UseMachineKeyStore = true;
                    return rsa;
                }
                catch (Exception)
                {
                    ((IDisposable) rsa)?.Dispose();
                    throw;
                }
            }
            catch (CryptographicException ex)
            {
                if (ex.Message.IndexOf("csp for this implementation could not be acquired", StringComparison.InvariantCultureIgnoreCase) > -1)
                {
                    var sb = new StringBuilder();
                    sb.Append("Unable to obtain Cryptographic Service Provider. ");
                    sb.Append("Either the permissions are incorrect on the ");
                    sb.Append(@"'C:\Documents and Settings\All Users\Application Data\Microsoft\Crypto\RSA\MachineKeys' or ");
                    sb.Append(@"'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys' ");
                    sb.Append("folder, or the current security context does not have access to this folder.");
                    throw new CryptographicException(sb.ToString(), ex);
                }
                throw;
            }
        }
    }

    internal static class KeyPairUtils
    {
        internal const string KeyModulus = "PublicKey.Modulus";
        internal const string KeyExponent = "PublicKey.Exponent";

        internal const string ElementParent = "RSAKeyValue";
        internal const string ElementModulus = "Modulus";
        internal const string ElementExponent = "Exponent";
        internal const string ElementPrimeP = "P";
        internal const string ElementPrimeQ = "Q";
        internal const string ElementPrimeExponentP = "DP";
        internal const string ElementPrimeExponentQ = "DQ";
        internal const string ElementCoefficient = "InverseQ";
        internal const string ElementPrivateExponent = "D";

        internal const string KeyPrimeP = "PrivateKey.P";
        internal const string KeyPrimeQ = "PrivateKey.Q";
        internal const string KeyPrimeExponentP = "PrivateKey.DP";
        internal const string KeyPrimeExponentQ = "PrivateKey.DQ";
        internal const string KeyCoefficient = "PrivateKey.InverseQ";
        internal const string KeyPrivateExponent = "PrivateKey.D";

        /// <summary>
        /// Gets an element from an XML string.
        /// </summary>
        internal static string GetXmlElement(string xml, string element)
        {
            var m = Regex.Match(xml, "<" + element + ">(?<Element>[^>]*)</" + element + ">", RegexOptions.IgnoreCase);
            if (m == null)
            {
                throw new XmlException("Could not find <" + element + "></" + element + "> in provided Public Key XML.");
            }
            return m.Groups["Element"].ToString();
        }




        internal static string WriteConfigKey(string key, string value)
        {
            var s = "<add key=\"{0}\" value=\"{1}\" />" + Environment.NewLine;
            return string.Format(CultureInfo.InvariantCulture, s, key, value);
        }

        internal static string WriteXmlElement(string element, string value)
        {
            var s = "<{0}>{1}</{0}>" + Environment.NewLine;
            return string.Format(CultureInfo.InvariantCulture, s, element, value);
        }

        internal static string WriteXmlNode(string element)
        {
            return WriteXmlNode(element, false);
        }

        internal static string WriteXmlNode(string element, bool isClosing)
        {
            string s;
            if (isClosing)
            {
                s = "</{0}>" + Environment.NewLine;
            }
            else
            {
                s = "<{0}>" + Environment.NewLine;
            }
            return string.Format(CultureInfo.InvariantCulture, s, element);
        }
    }

    #region PublicKey Class
    /// <summary>
    /// Represents a public encryption key.
    /// </summary>
    public class PublicKey
    {
        /// <summary>
        /// 
        /// </summary>
        public string Modulus { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string Exponent { get; set; }

        /// <summary>
        /// Initializes a new instance of the PublicKey class.
        /// </summary>
        public PublicKey()
        {

        }

        /// <summary>
        /// Initializes a new instance of the PublicKey class.
        /// </summary>
        public PublicKey(string keyXml)
        {
            LoadFromXml(keyXml);
        }


        /// <summary>
        /// Returns the *.config file XML section representing this public key.
        /// </summary>
        public string ToConfigSection()
        {
            var sb = new StringBuilder();
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyModulus, Modulus));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyExponent, Exponent));
            return sb.ToString();
        }

        /// <summary>
        /// Writes the *.config file representation of this public key to a file.
        /// </summary>
        public void ExportToConfigFile(string filePath)
        {
            using (var sw = new StreamWriter(filePath, false))
            {
                sw.Write(ToConfigSection());
            }
        }

        /// <summary>
        /// Loads the public key from an XML string.
        /// </summary>
        public void LoadFromXml(string keyXml)
        {
            Modulus = KeyPairUtils.GetXmlElement(keyXml, "Modulus");
            Exponent = KeyPairUtils.GetXmlElement(keyXml, "Exponent");
        }

        /// <summary>
        /// Converts this public key to an RSAParameters object.
        /// </summary>
        public RSAParameters ToParameters()
        {
            var r = new RSAParameters
            {
                Modulus = Convert.FromBase64String(Modulus),
                Exponent = Convert.FromBase64String(Exponent)
            };
            return r;
        }

        /// <summary>
        /// Converts this public key to its XML string representation.
        /// </summary>
        public string ToXml()
        {
            var sb = new StringBuilder();
            sb.Append(KeyPairUtils.WriteXmlNode(KeyPairUtils.ElementParent));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementModulus, Modulus));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementExponent, Exponent));
            sb.Append(KeyPairUtils.WriteXmlNode(KeyPairUtils.ElementParent, true));
            return sb.ToString();
        }

        /// <summary>
        /// Writes the XML representation of this public key to a file.
        /// </summary>
        public void ExportToXmlFile(string filePath)
        {
            using (var sw = new StreamWriter(filePath, false))
            {
                sw.Write(ToXml());
            }
        }
    }
    #endregion

    #region PrivateKey Class

    /// <summary>
    /// Represents a private encryption key.
    /// </summary>
    public class PrivateKey
    {
        /// <summary>
        /// 
        /// </summary>
        public string Modulus { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string Exponent { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string PrimeP { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string PrimeQ { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string PrimeExponentP { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string PrimeExponentQ { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string Coefficient { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public string PrivateExponent { get; set; }

        /// <summary>
        /// Initializes a new instance of the PrivateKey class.
        /// </summary>
        public PrivateKey()
        {

        }

        /// <summary>
        /// Initializes a new instance of the PrivateKey class.
        /// </summary>
        public PrivateKey(string keyXml)
        {
            LoadFromXml(keyXml);
        }

    

        /// <summary>
        /// Returns the *.config file XML section representing this private key.
        /// </summary>
        public string ToConfigSection()
        {
            var sb = new StringBuilder();
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyModulus, Modulus));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyExponent, Exponent));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyPrimeP, PrimeP));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyPrimeQ, PrimeQ));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyPrimeExponentP, PrimeExponentP));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyPrimeExponentQ, PrimeExponentQ));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyCoefficient, Coefficient));
            sb.Append(KeyPairUtils.WriteConfigKey(KeyPairUtils.KeyPrivateExponent, PrivateExponent));
            return sb.ToString();
        }

        /// <summary>
        /// Writes the *.config file representation of this private key to a file.
        /// </summary>
        public void ExportToConfigFile(string filePath)
        {
            using (var sw = new StreamWriter(filePath, false))
            {
                sw.Write(ToConfigSection());
            }
        }

        /// <summary>
        /// Loads the private key from an XML string.
        /// </summary>
        public void LoadFromXml(string keyXml)
        {
            Modulus = KeyPairUtils.GetXmlElement(keyXml, "Modulus");
            Exponent = KeyPairUtils.GetXmlElement(keyXml, "Exponent");
            PrimeP = KeyPairUtils.GetXmlElement(keyXml, "P");
            PrimeQ = KeyPairUtils.GetXmlElement(keyXml, "Q");
            PrimeExponentP = KeyPairUtils.GetXmlElement(keyXml, "DP");
            PrimeExponentQ = KeyPairUtils.GetXmlElement(keyXml, "DQ");
            Coefficient = KeyPairUtils.GetXmlElement(keyXml, "InverseQ");
            PrivateExponent = KeyPairUtils.GetXmlElement(keyXml, "D");
        }

        /// <summary>
        /// Converts this private key to an RSAParameters object.
        /// </summary>
        public RSAParameters ToParameters()
        {
            var r = new RSAParameters
            {
                Modulus = Convert.FromBase64String(Modulus),
                Exponent = Convert.FromBase64String(Exponent),
                P = Convert.FromBase64String(PrimeP),
                Q = Convert.FromBase64String(PrimeQ),
                DP = Convert.FromBase64String(PrimeExponentP),
                DQ = Convert.FromBase64String(PrimeExponentQ),
                InverseQ = Convert.FromBase64String(Coefficient),
                D = Convert.FromBase64String(PrivateExponent)
            };
            return r;
        }

        /// <summary>
        /// Converts this private key to its XML string representation.
        /// </summary>
        public string ToXml()
        {
            var sb = new StringBuilder();
            sb.Append(KeyPairUtils.WriteXmlNode(KeyPairUtils.ElementParent));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementModulus, Modulus));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementExponent, Exponent));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementPrimeP, PrimeP));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementPrimeQ, PrimeQ));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementPrimeExponentP, PrimeExponentP));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementPrimeExponentQ, PrimeExponentQ));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementCoefficient, Coefficient));
            sb.Append(KeyPairUtils.WriteXmlElement(KeyPairUtils.ElementPrivateExponent, PrivateExponent));
            sb.Append(KeyPairUtils.WriteXmlNode(KeyPairUtils.ElementParent, true));
            return sb.ToString();
        }

        /// <summary>
        /// Writes the XML representation of this private key to a file.
        /// </summary>
        public void ExportToXmlFile(string filePath)
        {
            using (var sw = new StreamWriter(filePath, false))
            {
                sw.Write(ToXml());
            }
        }
    }

    #endregion
}