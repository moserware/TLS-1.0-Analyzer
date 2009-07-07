using System;
using System.IO;
using System.Security.Cryptography;

namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// Implements the TLS 1.0 Pseudorandom Function (PRF)
    /// </summary>
    /// <remarks>
    /// The bulk of comments come from Section 5 of RFC 2246.
    /// Note that the PRF changed notably between TLS 1.0 and TLS 1.2. Only the 1.0 version is
    /// implemented here.
    /// </remarks>
    public static class Prf10
    {
        // PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
        //                            P_SHA-1(S2, label + seed);

        /// <summary>
        /// Generates bytes using the TLS 1.0 Pseudo-Random Function
        /// </summary>
        /// <param name="secret">The secret used for deriving bytes.</param>
        /// <param name="label">The ASCII label to use for deriving bytes.</param>
        /// <param name="seed">The seed used to derive bytes.</param>
        /// <param name="bytesToGenerate">The total number of bytes to generate.</param>
        /// <returns><paramref name="bytesToGenerate"/> derived bytes using the TLS 1.0 PRF function.</returns>
        public static byte[] GenerateBytes(byte[] secret, string label, byte[] seed, int bytesToGenerate)
        {            
            byte[] labelBytes = label.ToAsciiBytes();
            byte[] labelAndSeed = new byte[labelBytes.Length + seed.Length];

            // labelAndSeed = label + seed
            Buffer.BlockCopy(labelBytes, 0, labelAndSeed, 0, labelBytes.Length);
            Buffer.BlockCopy(seed, 0, labelAndSeed, labelBytes.Length, seed.Length);

            byte[] s1;
            byte[] s2;
            Split(secret, out s1, out s2);

            byte[] pMD5 = PMD5(s1, labelAndSeed, bytesToGenerate);
            byte[] pSHA1 = PSHA1(s2, labelAndSeed, bytesToGenerate);

            byte[] result = new byte[pMD5.Length];

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = (byte) (pMD5[i] ^ pSHA1[i]);
            }

            return result;
        }

        // (from Section 5 of RFC 2246)
        // TLS's PRF is created by splitting the secret into two halves and
        // using one half to generate data with P_MD5 and the other half to
        // generate data with P_SHA-1, then exclusive-or'ing the outputs of
        // these two expansion functions together.

        // S1 and S2 are the two halves of the secret and each is the same
        // length. S1 is taken from the first half of the secret, S2 from the
        // second half. Their length is created by rounding up the length of the
        // overall secret divided by two; thus, if the original secret is an odd
        // number of bytes long, the last byte of S1 will be the same as the
        // first byte of S2.

        //    L_S = length in bytes of secret;
        //    L_S1 = L_S2 = ceil(L_S / 2);

        internal static void Split(byte[] input, out byte[] s1, out byte[] s2)
        {
            int padding = (input.Length % 2);
            int halfSize = (input.Length / 2) + padding;

            s1 = new byte[halfSize];
            Buffer.BlockCopy(input, 0, s1, 0, halfSize);

            s2 = new byte[halfSize];
            Buffer.BlockCopy(input, input.Length - halfSize, s2, 0, halfSize);
        }

        // From section 5 of RFC 2246
        // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
        //                        HMAC_hash(secret, A(2) + seed) +
        //                        HMAC_hash(secret, A(3) + seed) + ...

        //   A() is defined as:
        //       A(0) = seed
        //       A(i) = HMAC_hash(secret, A(i-1))

        private static byte[] PHash(HMAC hmac, byte[] seed, int bytesToGenerate)
        {
            using(MemoryStream bytesToHashBuffer = new MemoryStream())
            using (MemoryStream output = new MemoryStream())
            {
                byte[] previousA = seed;

                while (output.Length < bytesToGenerate)
                {
                    bytesToHashBuffer.SetLength(0);

                    byte[] currentA = A(hmac, previousA);
                    bytesToHashBuffer.Write(currentA, 0, currentA.Length);
                    bytesToHashBuffer.Write(seed, 0, seed.Length);

                    byte[] currentBuffer = bytesToHashBuffer.GetBuffer();

                    byte[] currentRoundResult = hmac.ComputeHash(currentBuffer, 0, (int) bytesToHashBuffer.Length);
                    output.Write(currentRoundResult, 0, currentRoundResult.Length);
                    previousA = currentA;
                }

                output.SetLength(bytesToGenerate);

                return output.ToArray();
            }            
        }

        private static byte[] A(HMAC hmac, byte[] aMinus1Result)
        {            
            return hmac.ComputeHash(aMinus1Result);
        }

        private static byte[] PMD5(byte[] secret, byte[] seed, int bytesDesired)
        {
            return PHash(new HMACMD5(secret), seed, bytesDesired);
        }

        private static byte[] PSHA1(byte[] secret, byte[] seed, int bytesDesired)
        {
            return PHash(new HMACSHA1(secret), seed, bytesDesired);            
        }        
    }
}
