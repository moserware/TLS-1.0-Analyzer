using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace Moserware.TlsAnalyzer.UnitTests
{
    [TestFixture]
    public class Prf10Tests
    {
        [Test]
        public void CheckTestVector()
        {
            // Test Vector as defined in
            // http://www.imc.org/ietf-tls/mail-archive/msg01589.html 
            byte[] secret = new byte[48];
            
            for (int i = 0; i < secret.Length; i++)
            {
                secret[i] = 0xab;
            }

            string label = "PRF Testvector";

            byte[] seed = new byte[64];
            for (int i = 0; i < seed.Length; i++)
            {
                seed[i] = 0xcd;
            }

            int bytesToGenerate = 104;

            byte[] result = Prf10.GenerateBytes(secret, label, seed, bytesToGenerate);

            Assert.AreEqual(bytesToGenerate, result.Length);
            
            CollectionAssert.AreEqual(result, new byte[] {
                                      0xD3, 0xD4, 0xD1, 0xE3, 0x49, 0xB5, 0xD5, 0x15,
                                      0x04, 0x46, 0x66, 0xD5, 0x1D, 0xE3, 0x2B, 0xAB,
                                      0x25, 0x8C, 0xB5, 0x21, 0xB6, 0xB0, 0x53, 0x46, 
                                      0x3E, 0x35, 0x48, 0x32, 0xFD, 0x97, 0x67, 0x54,
                                      0x44, 0x3B, 0xCF, 0x9A, 0x29, 0x65, 0x19, 0xBC, 
                                      0x28, 0x9A, 0xBC, 0xBC, 0x11, 0x87, 0xE4, 0xEB,
                                      0xD3, 0x1E, 0x60, 0x23, 0x53, 0x77, 0x6C, 0x40, 
                                      0x8A, 0xAF, 0xB7, 0x4C, 0xBC, 0x85, 0xEF, 0xF6,
                                      0x92, 0x55, 0xF9, 0x78, 0x8F, 0xAA, 0x18, 0x4C, 
                                      0xBB, 0x95, 0x7A, 0x98, 0x19, 0xD8, 0x4A, 0x5D,
                                      0x7E, 0xB0, 0x06, 0xEB, 0x45, 0x9D, 0x3A, 0xE8, 
                                      0xDE, 0x98, 0x10, 0x45, 0x4B, 0x8B, 0x2D, 0x8F,
                                      0x1A, 0xFB, 0xC6, 0x55, 0xA8, 0xC9, 0xA0, 0x13});

            var md5 = new MD5CryptoServiceProvider();
            var hashedVector = md5.ComputeHash(result);

            CollectionAssert.AreEqual(new byte[] {
                                      0xCD, 0x7C, 0xA2, 0xCB, 0x9A, 0x6A, 0x3C, 0x6F,
                                      0x34, 0x5C, 0x46, 0x65, 0xA8, 0xB6, 0x81, 0x6B },
                                      hashedVector);
        }

        [Test]
        public void SplitTest()
        {
            byte[] deadBeef = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };

            byte[] deadBeefS1;
            byte[] deadBeefS2;

            Prf10.Split(deadBeef, out deadBeefS1, out deadBeefS2);
            CollectionAssert.AreEqual(new byte[] { 0xDE, 0xAD }, deadBeefS1);
            CollectionAssert.AreEqual(new byte[] { 0xBE, 0xEF }, deadBeefS2);

            // Get an odd one
            byte[] firstFive = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

            byte[] firstFiveS1;
            byte[] firstFiveS2;

            Prf10.Split(firstFive, out firstFiveS1, out firstFiveS2);
            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03 }, firstFiveS1);
            CollectionAssert.AreEqual(new byte[] { 0x03, 0x04, 0x05 }, firstFiveS2);

            // And an empty one for good measure
            byte[] empty = new byte[0];
            byte[] emptyS1;
            byte[] emptyS2;

            Prf10.Split(empty, out emptyS1, out emptyS2);
            Assert.AreEqual(0, emptyS1.Length);
            Assert.AreEqual(0, emptyS2.Length);
        }
                

        // HMAC Sanity checks from RFC 2202
        [Test]
        public void HMACMD5SanityCheck()
        {
            HMACSanityCheck(new HMACMD5(), 
                            0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
                            0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38);
        }

        [Test]
        public void HMACSHA1SanityCheck()
        {
            HMACSanityCheck(new HMACSHA1(),
                            0xef, 0xfc, 0xdf, 0x6a, 0xe5,
                            0xeb, 0x2f, 0xa2, 0xd2, 0x74,
                            0x16, 0xd5, 0xf1, 0x84, 0xdf,
                            0x9c, 0x25, 0x9a, 0x7c, 0x79);
        }

        private void HMACSanityCheck(HMAC hmac, params byte[] expected)
        {
            // test_case = 2
            string key = "Jefe";
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);

            string data = "what do ya want for nothing?";
            byte[] dataBytes = Encoding.ASCII.GetBytes(data);

            hmac.Key = keyBytes;
            byte[] digest = hmac.ComputeHash(dataBytes);

            CollectionAssert.AreEqual(expected, digest);
        }
    }
}
