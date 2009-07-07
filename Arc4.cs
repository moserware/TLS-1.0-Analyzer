namespace Moserware.TlsAnalyzer
{
    /// <summary>
    /// "Alleged RC4" Implementation
    /// </summary>
    /// <remarks>
    /// See pages 397-398 of "Applied Cryptography, 2nd Edition" by Bruce Schneier.
    /// The "alleged" part is for historical reasons (and that's how Firefox's NSS library refers to it).
    /// </remarks>
    public class Arc4
    {
        private byte[] _SubstitionBox = new byte[256];
        private byte[] _KeyingMaterial = new byte[256];
        private int _CounterI;
        private int _CounterJ;

        /// <summary>
        /// Initializes the algorithm with the <paramref name="key"/>.
        /// </summary>
        /// <param name="key">The key to use for encryption/decryption.</param>
        public Arc4(byte[] key)
        {
            // "Fill it linearly"
            for (int i = 0; i < 256; i++)
            {
                _SubstitionBox[i] = (byte)i;
            }

            // "fill another 256-byte array with the key, 
            // repeating the key as necessary to fill the entire array"
            for (int i = 0; i < 256; i++)
            {
                _KeyingMaterial[i] = key[i % key.Length];
            }

            int j = 0;

            for (int i = 0; i < 256; i++)
            {
                j = (j + _SubstitionBox[i] + _KeyingMaterial[i]) % 256;

                // Swap S[i] and S[j]
                Swap(ref _SubstitionBox[i], ref _SubstitionBox[j]);                
            }

            // "And that's it."
        }

        private static void Swap(ref byte b1, ref byte b2)
        {
            byte temp = b1;
            b1 = b2;
            b2 = temp;
        }

        /// <summary>
        /// Encrypts the <paramref name="input"/>.
        /// </summary>
        /// <param name="input">The plaintext bytes that will be encrypted</param>
        public byte[] Encrypt(byte[] input)
        {
            byte[] encryptedValue = new byte[input.Length];

            for (int i = 0; i < input.Length; i++)
            {
                encryptedValue[i] = (byte) (GetNextByte() ^ input[i]);
            }

            return encryptedValue;
        }

        private byte GetNextByte()
        {
            _CounterI = (_CounterI + 1) % 256;
            _CounterJ = (_CounterJ + _SubstitionBox[_CounterI]) % 256;
            Swap(ref _SubstitionBox[_CounterI], ref _SubstitionBox[_CounterJ]);
            byte t = (byte) ((_SubstitionBox[_CounterI] + _SubstitionBox[_CounterJ]) % 256);
            return _SubstitionBox[t];
        }
    }
}
