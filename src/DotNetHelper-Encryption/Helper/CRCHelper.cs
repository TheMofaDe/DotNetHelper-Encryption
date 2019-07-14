using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetHelper_Encryption.Helper
{
    public static class CRCHelper
    {
        public static string GetCRC(Stream stream,bool disposeStream)
        {
            if (disposeStream)
            {
                using (stream)
                {
                    var hash = string.Empty;
                    var bytes = HashingFactory.Create(HashProvider.CRC32).ComputeHash(stream);
                    hash = bytes.Aggregate(hash, (current, b) => current + b.ToString("x2").ToLower());
                    return hash;
                }
            }
            else
            {
                var hash = string.Empty;
                var bytes = HashingFactory.Create(HashProvider.CRC32).ComputeHash(stream);
                hash = bytes.Aggregate(hash, (current, b) => current + b.ToString("x2").ToLower());
                return hash;
            }

        }
    }
}
