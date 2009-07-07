using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace Moserware.TlsAnalyzer.UnitTests
{
    [TestFixture]
    public class WiresharkClipboardUtilitiesTests
    {
        [Test]
        public void FromWiresharkTest()
        {
            // eg. "160301"
            var result = "160301".FromWireshark();
            CollectionAssert.AreEqual(new byte[] { 0x16, 0x03, 0x01 }, result);
        }
    }
}
