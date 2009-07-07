using NUnit.Framework;

namespace Moserware.TlsAnalyzer.UnitTests
{
    [TestFixture]
    public class ByteUtilitiesTest
    {
        [Test]
        public void ToDisplayByteStringTest()
        {
            Assert.AreEqual("01 23 45 67", (new byte[] { 0x01, 0x23, 0x45, 0x67 }).ToDisplayByteString());
            Assert.AreEqual("0123 4567", (new byte[] { 0x01, 0x23, 0x45, 0x67}).ToDisplayByteString(2));
            Assert.AreEqual("00000000000000000000000001234567", (new byte[] { 0x01, 0x23, 0x45, 0x67 }).ToDisplayByteString(16));            
        }
    }
}
