using System.Text;
using Mono.Math;

namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// Utilities for <see cref="BigInteger"/>s.
    /// </summary>
    public static class BigIntegerUtilities
    {
        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a base-10 representation that's in groups of 10.
        /// </summary>
        /// <param name="bigInteger">The integer to display.</param>
        /// <returns>A base-10 representation of <paramref name="bigInteger"/> with digit groups of 10 digits.</returns>
        public static string ToDisplayString(this BigInteger bigInteger)
        {
            var sb = new StringBuilder();
            string base10 = bigInteger.ToString();

            for (int i = 0; i < base10.Length; i++)
            {
                if ((i % 10 == 0) && (i > 0))
                {
                    sb.Append(" ");
                }
                sb.Append(base10[i]);
            }

            return sb.ToString();
        }
    }
}
