using System.Text;
using NUnit.Framework;

namespace Moserware.TlsAnalyzer.UnitTests
{
    [TestFixture]
    public class Arc4Tests
    {
        [Test]
        public void WikipediaTestVectors()
        {
            // See http://en.wikipedia.org/wiki/RC4#Test_vectors for 25 May 2009
            AssertWikipediaVector("Key", "Plaintext", 0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3);
            AssertWikipediaVector("Wiki", "pedia", 0x10, 0x21, 0xBF, 0x04, 0x20);
            AssertWikipediaVector("Secret", "Attack at dawn", 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5);
        }

        private static void AssertWikipediaVector(string key, string plainText, params byte[] expected)
        {
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);
            byte[] result = Encoding.ASCII.GetBytes(plainText);
            var arc4 = new Arc4(keyBytes);
            var encryptedResult = arc4.Encrypt(result);

            CollectionAssert.AreEqual(expected, encryptedResult);
        }
    }
}
