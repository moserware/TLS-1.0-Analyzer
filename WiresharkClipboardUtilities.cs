using System;
using System.Text.RegularExpressions;

namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// Extension methods for working with Wireshark
    /// </summary>
    public static class WiresharkClipboardUtilities
    {
        /// <summary>
        /// Creates a byte array from a string that was created using the copy "Bytes (Hex Stream)" method in Wireshark.
        /// </summary>
        /// <param name="clipboardValue">A string that was created using the copy "Bytes (Hex Stream)" method in Wireshark.</param>
        /// <returns>A byte array derived from the hex stream <paramref name="clipboardValue"/>.</returns>
        public static byte[] FromWireshark(this string clipboardValue)
        {
            clipboardValue = Regex.Replace(clipboardValue, @"\s", "");
            // like "160301"            
            byte[] result = new byte[clipboardValue.Length / 2];

            for (int i = 0; i < clipboardValue.Length; i += 2)
            {
                string currentStringByte = clipboardValue.Substring(i, 2);
                byte currentByte = Convert.ToByte(currentStringByte, 16);
                result[i / 2] = currentByte;
            }

            return result;
        }
    }
}
