using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using System.Security.Cryptography;

namespace Moserware.TlsAnalyzer.UnitTests
{
    [TestFixture]
    public class FirefoxSslDebugFileUtilitiesTest
    {
        [Test]
        public void GetPremasterSecretKeyTest()
        {            
            string input = @"5140: SSL[75821480]: Pre-Master Secret [Len: 48]
                             03 01 97 01 9e aa 3c 3c e1 ef 7f 39 5d be 88 1e   ......<<...9]...
                             60 51 e7 f5 94 db fd 62 b2 b5 26 be b5 3d 7c 16   `Q.....b..&..=|.
                             4d ff 79 73 8e cb c8 aa 9c 70 f2 5d 29 91 72 50   M.ys.....p.]).rP";
            byte[] result = FirefoxSslDebugFileUtilities.GetPremasterSecretKey(input);
            CollectionAssert.AreEqual(new byte[] { 
                                      0x03, 0x01, 0x97, 0x01, 0x9e, 0xaa, 0x3c, 0x3c, 
                                      0xe1, 0xef, 0x7f, 0x39, 0x5d, 0xbe, 0x88, 0x1e,
                                      0x60, 0x51, 0xe7, 0xf5, 0x94, 0xdb, 0xfd, 0x62, 
                                      0xb2, 0xb5, 0x26, 0xbe, 0xb5, 0x3d, 0x7c, 0x16,
                                      0x4d, 0xff, 0x79, 0x73, 0x8e, 0xcb, 0xc8, 0xaa, 
                                      0x9c, 0x70, 0xf2, 0x5d, 0x29, 0x91, 0x72, 0x50 }
                                      , result);
        }
    }
}
