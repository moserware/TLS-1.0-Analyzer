using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// Utilities to help with <see cref="Byte"/>s.
    /// </summary>
    public static class ByteUtilities
    {
        /// <summary>
        /// Performs <paramref name="a"/> xor <paramref name="b"/>.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns><paramref name="a"/> xor <paramref name="b"/></returns>
        public static byte[] Xor(this byte[] a, byte[] b)
        {
            if (a.Length > b.Length)
            {
                throw new ArgumentException("'a' must be smaller than or equal to 'b'");
            }

            byte[] result = new byte[b.Length];

            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }

            for (int i = a.Length; i < b.Length; i++)
            {
                result[i] = b[i];
            }

            return result;
        }

        /// <summary>
        /// Concatenates byte arrays into a single byte array.
        /// </summary>
        /// <param name="byteArrays">An array containing all the byte arrays to combine.</param>
        /// <returns>A combined array of all of the individual arrays in <paramref name="byteArrays"/>.</returns>
        public static byte[] ConcatBytes(params byte[][] byteArrays)
        {
            using(var ms = new MemoryStream())
            {
                foreach(byte[] currentArray in byteArrays)
                {
                    ms.Write(currentArray, 0, currentArray.Length);
                }

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Determines if two byte arrays are equivalent.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns><see langword="true"/> if the byte arrays are equal; otherwise, <see langword="false"/>.</returns>
        public static bool AreEqual(byte[] a, byte[] b)
        {
            if(a.Length != b.Length)
            {
                return false;
            }

            for(int i = 0; i < a.Length; i++)
            {
                if(a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Formats the bytes for display into single byte segments.
        /// </summary>
        /// <param name="bytes">Array to convert to a display string.</param>
        /// <returns>Formatted display byte string.</returns>
        public static string ToDisplayByteString(this byte[] bytes)
        {
            return ToDisplayByteString(bytes, 1);
        }

        /// <summary>
        /// Gets the ASCII byte represetnation of <paramref name="s"/>.
        /// </summary>
        /// <param name="s">The string to get the ASCII byte representation of.</param>
        /// <returns>The ASCII byte representation of <paramref name="s"/>.</returns>
        public static byte[] ToAsciiBytes(this string s)
        {
            return Encoding.ASCII.GetBytes(s);
        }

        /// <summary>
        /// Formats the bytes for display into <param name="byteGroupSize"/> byte segments.
        /// </summary>
        /// <param name="bytes">Array to convert to a display string.</param>
        /// <returns>Formatted display byte string.</returns>
        public static string ToDisplayByteString(this byte[] bytes, int byteGroupSize)
        {                      
            int remainderBytes = (bytes.Length % byteGroupSize);
            int extraBytesNeeded = (remainderBytes == 0) ? 0 : (byteGroupSize - remainderBytes);
            StringBuilder sb = new StringBuilder();

            int totalBytes = bytes.Length + extraBytesNeeded;
                        
            for (int i = 0; i < totalBytes; i++)
            {
                if (((i % byteGroupSize) == 0) && (i > 0))
                {
                    // Add a space between the byte groups
                    sb.Append(" ");
                }

                if (i < extraBytesNeeded)
                {
                    // Add pad bytes
                    sb.Append("00");
                }
                else
                {
                    byte currentByte = bytes[i - extraBytesNeeded];
                    sb.Append(currentByte.ToString("X2", CultureInfo.InvariantCulture));
                }                
            }

            return sb.ToString();
        }

        /// <summary>
        /// Return a <paramref name="length"/> length subset of <paramref name="bytes"/> starting at <paramref name="startIndex"/>.
        /// </summary>
        /// <param name="bytes">The byte array to take a subset of.</param>
        /// <param name="startIndex">The zero-based starting index of subset.</param>
        /// <param name="length">The total bytes to have in the subset.</param>
        /// <returns>A <paramref name="length"/> length subset of <paramref name="bytes"/> starting at <paramref name="startIndex"/>.</returns>
        public static byte[] SubBytes(this byte[] bytes, int startIndex, int length)
        {
            using (var ms = new MemoryStream())
            {
                ms.Write(bytes, startIndex, length);
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Return a subset of <paramref name="bytes"/> starting at <paramref name="startIndex"/>.
        /// </summary>
        /// <param name="bytes">The byte array to take a subset of.</param>
        /// <param name="startIndex">The zero-based starting index of subset.</param>        
        /// <returns>A subset of <paramref name="bytes"/> starting at <paramref name="startIndex"/>.</returns>
        public static byte[] SubBytes(this byte[] bytes, int startIndex)
        {
            return SubBytes(bytes, startIndex, bytes.Length - startIndex);
        }        
    }
}
