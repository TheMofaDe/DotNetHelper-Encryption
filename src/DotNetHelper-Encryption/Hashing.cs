using System;
using System.Security.Cryptography;
using System.Text;

namespace DotNetHelper_Encryption
{
    // A simple, string-oriented wrapper class for encryption functions, including 
    // Hashing, Symmetric Encryption, and Asymmetric Encryption.
    //
    //   Jeff Atwood
    //   http://www.codinghorror.com/
    //   http://www.codeproject.com/KB/security/SimpleEncryption.aspx
    //   https://github.com/harlam357/harlam357-net/blob/0454f68fda0270a39db279fc26a32c727d66ca97/Core/Security/Hash.cs

    /// <summary>
    /// Specifies the type of hash.
    /// </summary>
    public enum HashProvider
    {
        // ReSharper disable InconsistentNaming

        /// <summary>
        /// Cyclic Redundancy Check provider, 32-bit.
        /// </summary>
        CRC32,

        /// <summary>
        /// Secure Hashing Algorithm provider, SHA-1 variant, 160-bit.
        /// </summary>
        SHA1,

        /// <summary>
        /// Secure Hashing Algorithm provider, SHA-2 variant, 256-bit.
        /// </summary>
        SHA256,

        /// <summary>
        /// Secure Hashing Algorithm provider, SHA-2 variant, 384-bit.
        /// </summary>
        SHA384,

        /// <summary>
        /// Secure Hashing Algorithm provider, SHA-2 variant, 512-bit.
        /// </summary>
        SHA512,

        /// <summary>
        /// Message Digest algorithm 5, 128-bit.
        /// </summary>
        MD5

        // ReSharper restore InconsistentNaming
    }

    /// <summary>
    /// Provides access to factory methods for creating HashAlgorithm instances.
    /// </summary>
    public static class Hashing
    {


        
        /// <summary>
        /// Creates a new instance of the HashAlgorithm class based on the specified provider.
        /// </summary>
        /// <param name="provider">Provides the type of hash algorithm to create.</param>
        /// <returns>The HashAlgorithm object.</returns>
        /// <exception cref="T:System.ArgumentException">The provider is unknown.</exception>
        public static HashAlgorithm Create(HashProvider provider)
        {
            switch (provider)
            {
                case HashProvider.CRC32:
                    return new CRC32();
                case HashProvider.SHA1:
                    return SHA1.Create();
                case HashProvider.SHA256:
                    return SHA256.Create();
                case HashProvider.SHA384:
                    return SHA384.Create();
                case HashProvider.SHA512:
                    return SHA512.Create();
                case HashProvider.MD5:
                    return MD5.Create();
                default:
                    break;
            }

            throw new ArgumentException("Unknown HashProvider.", nameof(provider));
        }

        #region CRC32 HashAlgorithm

        // ReSharper disable InconsistentNaming
        private sealed class CRC32 : HashAlgorithm
            // ReSharper restore InconsistentNaming
        {
            private const uint DefaultPolynomial = 0xedb88320;
            private const uint DefaultSeed = 0xffffffff;

            private uint _hash;
            private readonly uint _seed;
            private readonly uint[] _table;
            private static uint[] _defaultTable;

            public CRC32()
            {
                _table = InitializeTable(DefaultPolynomial);
                _seed = DefaultSeed;
                Initialize();
            }

            //public CRC32(UInt32 polynomial, UInt32 seed)
            //{
            //   _table = InitializeTable(polynomial);
            //   _seed = seed;
            //   Initialize();
            //}

            public override void Initialize()
            {
                _hash = _seed;
            }

            protected override void HashCore(byte[] buffer, int start, int length)
            {
                _hash = CalculateHash(_table, _hash, buffer, start, length);
            }

            protected override byte[] HashFinal()
            {
                var hashBuffer = UInt32ToBigEndianBytes(~_hash);
                HashValue = hashBuffer;
                return hashBuffer;
            }

            public override int HashSize => 32;

            //public static UInt32 Compute(byte[] buffer)
            //{
            //   return ~CalculateHash(InitializeTable(DefaultPolynomial), DefaultSeed, buffer, 0, buffer.Length);
            //}

            //public static UInt32 Compute(UInt32 seed, byte[] buffer)
            //{
            //   return ~CalculateHash(InitializeTable(DefaultPolynomial), seed, buffer, 0, buffer.Length);
            //}

            //public static UInt32 Compute(UInt32 polynomial, UInt32 seed, byte[] buffer)
            //{
            //   return ~CalculateHash(InitializeTable(polynomial), seed, buffer, 0, buffer.Length);
            //}

            private static uint[] InitializeTable(uint polynomial)
            {
                if (polynomial == DefaultPolynomial && _defaultTable != null)
                {
                    return _defaultTable;
                }

                var createTable = new uint[256];
                for (var i = 0; i < 256; i++)
                {
                    var entry = (uint) i;
                    for (var j = 0; j < 8; j++)
                    {
                        if ((entry & 1) == 1)
                        {
                            entry = (entry >> 1) ^ polynomial;
                        }
                        else
                        {
                            entry = entry >> 1;
                        }
                    }

                    createTable[i] = entry;
                }

                if (polynomial == DefaultPolynomial)
                {
                    _defaultTable = createTable;
                }

                return createTable;
            }

            private static uint CalculateHash(uint[] table, uint seed, byte[] buffer, int start, int size)
            {
                var crc = seed;
                for (var i = start; i < size; i++)
                {
                    unchecked
                    {
                        crc = (crc >> 8) ^ table[buffer[i] ^ crc & 0xff];
                    }
                }
                return crc;
            }

            private static byte[] UInt32ToBigEndianBytes(uint x)
            {
                return new[]
                {
                    (byte) ((x >> 24) & 0xff),
                    (byte) ((x >> 16) & 0xff),
                    (byte) ((x >> 8) & 0xff),
                    (byte) (x & 0xff)
                };
            }

        }

        #endregion
    }

    // Hash functions are fundamental to modern cryptography. These functions map binary 
    // strings of an arbitrary length to small binary strings of a fixed length, known as 
    // hash values. A cryptographic hash function has the property that it is computationally
    // infeasible to find two distinct inputs that hash to the same value. Hash functions 
    // are commonly used with digital signatures and for data integrity.

    /// <summary>
    /// Represents an object that performs hashing.
    /// </summary>
    public class Hash : IDisposable
    {
        private readonly HashAlgorithm _hash;

        /// <summary>
        /// Initializes a new instance of the Hash class with the specified hash provider.
        /// </summary>
        public Hash(HashProvider provider)
        {
            _hash = Hashing.Create(provider);
        }

        /// <summary>
        /// Gets the previously calculated hash value.
        /// </summary>
        public PreEncryptData Value { get; } = new PreEncryptData();

        /// <summary>
        /// Calculates the hash on a stream of arbitrary length.
        /// </summary>
        public PreEncryptData Calculate(System.IO.Stream stream)
        {
            Value.Bytes = _hash.ComputeHash(stream);
            return Value;
        }

        /// <summary>
        /// Calculates the hash for fixed length data.
        /// </summary>
        /// <exception cref="T:System.ArgumentNullException">data is null.</exception>
        public PreEncryptData Calculate(PreEncryptData data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            return CalculatePrivate(data.Bytes);
        }

        /// <summary>
        /// Calculates the hash for fixed length data with a prefixed salt value.
        ///  </summary>
        /// <exception cref="T:System.ArgumentNullException">data or salt is null.</exception>
        /// <remarks>A "salt" value is random data prefixed to every hashed value to prevent common dictionary attacks.</remarks>
        public PreEncryptData Calculate(PreEncryptData data, PreEncryptData salt)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (salt == null) throw new ArgumentNullException(nameof(salt));

            var value = new byte[data.Bytes.Length + salt.Bytes.Length];
            salt.Bytes.CopyTo(value, 0);
            data.Bytes.CopyTo(value, salt.Bytes.Length);
            return CalculatePrivate(value);
        }

        private PreEncryptData CalculatePrivate(byte[] value)
        {
            Value.Bytes = _hash.ComputeHash(value);
            return Value;
        }

        /// <summary>
        /// Calculates the hash on a seekable stream while reporting progress.
        /// </summary>
        public PreEncryptData Calculate(System.IO.Stream stream, IProgress<int> progress)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (progress == null) throw new ArgumentNullException(nameof(progress));
            if (!stream.CanSeek) throw new ArgumentException("stream must support seeking.", nameof(stream));

            const int bufferLength = 1048576;
            long totalBytesRead = 0;
            var size = stream.Length;
            var buffer = new byte[bufferLength];

            var bytesRead = stream.Read(buffer, 0, buffer.Length);
            totalBytesRead += bytesRead;

            do
            {
                var oldBytesRead = bytesRead;
                var oldBuffer = buffer;

                buffer = new byte[bufferLength];
                bytesRead = stream.Read(buffer, 0, buffer.Length);

                totalBytesRead += bytesRead;

                if (bytesRead == 0)
                {
                    _hash.TransformFinalBlock(oldBuffer, 0, oldBytesRead);
                }
                else
                {
                    _hash.TransformBlock(oldBuffer, 0, oldBytesRead, oldBuffer, 0);
                }

                progress.Report((int) ((double) totalBytesRead * 100 / size));

            } while (bytesRead != 0);

            Value.Bytes = _hash.Hash;
            return Value;
        }

        #region IDisposable Implementation

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        /// <filterpriority>2</filterpriority>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        /// <filterpriority>2</filterpriority>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // clean managed resources
                    ((IDisposable) _hash).Dispose();
                }
                // clean unmanaged resources
            }

            _disposed = true;
        }

        private bool _disposed;

        #endregion







        /// <summary>
        /// Represents data to encrypt or decrypt.
        /// </summary>
        /// <remarks>
        /// Use the Text property to get/set a string representation.
        /// </remarks>
        public class PreEncryptData
        {
            #region Fields

            private byte[] _data;

            /// <summary>
            /// Gets the default text encoding for all Data instances.
            /// </summary>
            public static Encoding DefaultEncoding { get; } = Encoding.GetEncoding("utf-8"); // Encoding.GetEncoding("Windows-1252");

            private Encoding _encoding = DefaultEncoding;
            /// <summary>
            /// Gets or sets the text encoding for this Data instance.
            /// </summary>
            public Encoding Encoding
            {
                get => _encoding ?? (_encoding = DefaultEncoding);
                set => _encoding = value;
            }

            #endregion

            #region Constructors

            /// <summary>
            /// Initializes a new instance of the Data class that is empty.
            /// </summary>
            public PreEncryptData()
            {

            }

            /// <summary>
            /// Initializes a new instance of the Data class with the byte array value.
            /// </summary>
            public PreEncryptData(byte[] value)
            {
                _data = value;
            }

            /// <summary>
            /// Initializes a new instance of the Data class with the string value.
            /// </summary>
            public PreEncryptData(string value)
            {
                Text = value;
            }

            /// <summary>
            /// Initializes a new instance of the Data class with the string value.
            /// </summary>
            public PreEncryptData(string value, Encoding encoding)
            {
                // encoding must be set BEFORE value
                Encoding = encoding;
                Text = value;
            }

            #endregion

            #region Properties

            /// <summary>
            /// Indicates if no data is present in this instance.
            /// </summary>
            public bool IsEmpty => _data == null || _data.Length == 0;

            /// <summary>
            /// Gets or sets the byte representation of the data.
            /// </summary>
            public virtual byte[] Bytes
            {
                get => _data;
                set => _data = value;
            }

            /// <summary>
            /// Gets or sets the text representation of the data using the Encoding value.
            /// </summary>
            public string Text
            {
                get
                {
                    if (_data == null)
                    {
                        return string.Empty;
                    }

                    // need to handle nulls here
                    // oddly, C# will happily convert nulls into the string
                    // whereas VB stops converting at the first null
                    var i = Array.IndexOf(_data, (byte)0);
                    if (i >= 0)
                    {
                        return Encoding.GetString(_data, 0, i);
                    }
                    return Encoding.GetString(_data);
                }
                set => _data = Encoding.GetBytes(value);
            }

            #endregion

            /// <summary>
            /// Returns a string that represents the current object.
            /// </summary>
            /// <returns>A string that represents the current object.</returns>
            /// <filterpriority>2</filterpriority>
            public override string ToString()
            {
                return Text;
            }
        }
    
}











}