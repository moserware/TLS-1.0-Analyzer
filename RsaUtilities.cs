using Mono.Math;

namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// Utility methods for working with the RSA algorithm.
    /// </summary>
    public static class RsaUtilities
    {
        /// <summary>
        /// Performs the RSA operation Result = <paramref name="message"/>^<paramref name="exponent"/> (mod <paramref name="modulus"/>).
        /// </summary>
        /// <param name="message">The message to perform the operation on.</param>
        /// <param name="exponent">The exponent value to raise the message by.</param>
        /// <param name="modulus">The modulus to divide the results by.</param>
        /// <returns>The value C, such that C = <paramref name="message"/>^<paramref name="exponent"/> (mod <paramref name="modulus"/>).</returns>
        public static byte[] PublicKeyOperation(byte[] message, byte[] exponent, byte[] modulus)
        {
            var m = new BigInteger(message);
            var e = new BigInteger(exponent);
            var n = new BigInteger(modulus);
            var c = m.ModPow(e, n);
            var resultBytes = c.GetBytes();
            
            return resultBytes;
        }

        // Redundant functions whose name sounds better and have better IntelliSense...

        /// <summary>
        /// Encrypts a message using the RSA algorithm.
        /// </summary>
        /// <param name="plainText">The message to encrypt.</param>
        /// <param name="publicExponent">The public exponent of the recipient.</param>
        /// <param name="modulus">The modulus of the recipient.</param>
        /// <returns>The value C, such that C = <paramref name="plainText"/>^<paramref name="publicExponent"/> (mod <paramref name="modulus"/>).</returns>
        public static byte[] Encrypt(byte[] plainText, byte[] publicExponent, byte[] modulus)
        {
            return PublicKeyOperation(plainText, publicExponent, modulus);
        }

        /// <summary>
        /// Gets the original signed value using the RSA algorithm.
        /// </summary>
        /// <param name="signedValue">The encrypted signed value.</param>
        /// <param name="publicExponent">The signer's public key.</param>
        /// <param name="modulus">The signer's modulus.</param>
        /// <returns>The value M, such that M = <paramref name="signedValue"/>^<paramref name="publicExponent"/> (mod <paramref name="modulus"/>).</returns>
        public static byte[] GetSignedOriginalValue(byte[] signedValue, byte[] publicExponent, byte[] modulus)
        {
            return PublicKeyOperation(signedValue, publicExponent, modulus);            
        }
    }
}
