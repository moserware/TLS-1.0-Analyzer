using System;
using System.Text;
using Mono.Math;
using NUnit.Framework;

namespace Moserware.TlsAnalyzer.UnitTests
{
    [TestFixture]
    public class BigIntegerTests
    {
        [Test]
        public void WikipediaSanityChecks()
        {
            // http://en.wikipedia.org/wiki/RSA on 25 May 2009
            var c = new BigInteger(855);
            var d = new BigInteger(2753);
            var n = new BigInteger(3233);
            var m = c.ModPow(d, n);
            Assert.AreEqual("123", m.ToString());           
        }

        [Test]
        public void AppliedCryptographySanityChecks()
        {
            // Sanity checks from Applied Cryptography, 2nd Edition p467 - 468
            var p = new BigInteger(47);
            var q = new BigInteger(71);
            var n = p * q;
            var e = new BigInteger(79);
            var d = e.ModInverse((p - 1) * (q - 1));
            Func<int, string> encryptor = m => (new BigInteger(m).ModPow(e, n)).ToString();
            Assert.AreEqual("1570", encryptor(688));
            Assert.AreEqual("2756", encryptor(232));
            Assert.AreEqual("2091", encryptor(687));
            Assert.AreEqual("2276", encryptor(966));
            Assert.AreEqual("2423", encryptor(668));
            Assert.AreEqual("158", encryptor(3));            
        }
    }
}
