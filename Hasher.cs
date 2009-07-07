using System;
using System.Net;
using System.Security.Cryptography;

namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// Provides some simple wrappers around hash functions.
    /// </summary>
    public static class Hasher
    {
        private static readonly SHA1Managed _SHA1 = new SHA1Managed();
        private static readonly MD5 _MD5 = new MD5CryptoServiceProvider();
        private static readonly HMACMD5 _HmacMd5 = new HMACMD5();
        private static readonly HMACSHA1 _HmacSha1 = new HMACSHA1();

        /// <summary>
        /// Computes the SHA-1 hash.
        /// </summary>
        /// <param name="inputBytes">The bytes to compute the hash of.</param>
        /// <returns>The 20 byte SHA-1 digest of <paramref name="inputBytes"/>.</returns>
        public static byte[] ComputeSHA1Hash(byte[] inputBytes)
        {
            return _SHA1.ComputeHash(inputBytes);
        }

        /// <summary>
        /// Computes the keyed HMAC version of the SHA-1 hash.
        /// </summary>
        /// <param name="key">The key to use for the HMAC operation.</param>
        /// <param name="inputBytes">The bytes to compute the hash of.</param>
        /// <returns>The 20 byte HMAC SHA-1 digest of <paramref name="inputBytes"/> using <paramref name="key"/>.</returns>
        public static byte[] ComputeSHA1Hmac(byte[] key, byte[] inputBytes)
        {
            _HmacSha1.Key = key;
            return _HmacSha1.ComputeHash(inputBytes);
        }

        /// <summary>
        /// Computes the MD5 hash.
        /// </summary>
        /// <param name="inputBytes">The bytes to compute the hash of.</param>
        /// <returns>The 16 byte MD5 digest of <paramref name="inputBytes"/>.</returns>
        public static byte[] ComputeMD5(byte[] inputBytes)
        {
            return _MD5.ComputeHash(inputBytes);
        }

        /// <summary>
        /// Computes the keyed HMAC version of the MD5 hash.
        /// </summary>
        /// <param name="key">The key to use for the HMAC operation.</param>
        /// <param name="inputBytes">The bytes to compute the hash of.</param>
        /// <returns>The 16 byte HMAC MD5 digest of <paramref name="inputBytes"/> using <paramref name="key"/>.</returns>
        public static byte[] ComputeMD5Hmac(byte[] key, byte[] data)
        {
            _HmacMd5.Key = key;
            return _HmacMd5.ComputeHash(data);
        }

        // HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
        //           TLSCompressed.version + TLSCompressed.length +
        //           TLSCompressed.fragment));

        /// <summary>
        /// Computes the TLS 1.0 MD5 HMAC for a record.
        /// </summary>
        /// <param name="secret">The secret to use for the HMAC calculation.</param>
        /// <param name="contentType">The TLS record content type.</param>
        /// <param name="sequenceNumber">The sequence number of the fragment.</param>
        /// <param name="fragment">The data sent.</param>
        /// <returns>The 16 byte HMAC hash.</returns>
        public static byte[] ComputeTlsMD5Hmac(byte[] secret, byte contentType, long sequenceNumber, byte[] fragment)
        {
            _HmacMd5.Key = secret;

            return _HmacMd5.ComputeHash(
                    ByteUtilities.ConcatBytes(
                            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(sequenceNumber)),
                            new [] { contentType }, 
                            new byte[] {3, 1}, // version
                            BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short) fragment.Length)),
                            fragment));
        }
    }
}
