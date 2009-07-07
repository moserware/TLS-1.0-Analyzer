using System;
using System.IO;

namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// Utilities to work with Firefox's debug files.
    /// </summary>
    public static class FirefoxSslDebugFileUtilities
    {
        /// <summary>
        /// Helper function for things dumped to SSLDEBUGFILE with appropriate SSLTRACE levels.
        /// </summary>
        /// <param name="input">Raw input that has the pre-master secret.</param>
        /// <returns>The pre-master secret key bytes.</returns>
        public static byte[] GetPremasterSecretKey(string input)
        {
            // Looks like
            // 5140: SSL[75821480]: Pre-Master Secret [Len: 48]
            // 03 01 97 01 9e aa 3c 3c e1 ef 7f 39 5d be 88 1e   ......<<...9]...
            // 60 51 e7 f5 94 db fd 62 b2 b5 26 be b5 3d 7c 16   `Q.....b..&..=|.
            // 4d ff 79 73 8e cb c8 aa 9c 70 f2 5d 29 91 72 50   M.ys.....p.]).rP
            using (var sr = new StringReader(input))
            {
                bool foundHeader = false;

                while (sr.Peek() >= 0)
                {
                    string currentLine = sr.ReadLine().Trim();
                    if (!foundHeader)
                    {
                        if (!currentLine.Contains("Pre-Master Secret"))
                        {
                            continue;
                        }

                        foundHeader = true;
                        break;
                    }
                }

                if (!foundHeader)
                {
                    throw new InvalidDataException();
                }

                // reading in secret bytes
                using (var ms = new MemoryStream())
                {
                    for (int ixCurrentLine = 0; ixCurrentLine < 3; ixCurrentLine++)
                    {
                        string currentLine = sr.ReadLine().Trim();
                        for (int ixCurrentByte = 0; ixCurrentByte < 16; ixCurrentByte++)
                        {
                            string byteText = currentLine.Substring(3 * ixCurrentByte, 2);
                            ms.WriteByte(Convert.ToByte(byteText, 16));
                        }
                    }

                    return ms.ToArray();
                }                
            }            
        }
    }
}
