using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Mono.Math;

namespace Moserware.TlsAnalyzer
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }

        private void btnGo_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] preMasterSecret = FirefoxSslDebugFileUtilities.GetPremasterSecretKey(txtPremasterSecret.Text);
                string label = txtMasterSecretLabel.Text;

                byte[] serverHelloRandom = txtServerRandomBytes.Text.FromWireshark();
                byte[] clientHelloRandom = txtClientRandomBytes.Text.FromWireshark();

                byte[] clientHelloAndServerHello = ByteUtilities.ConcatBytes(clientHelloRandom, serverHelloRandom);

                byte[] masterSecret = Prf10.GenerateBytes(preMasterSecret, label, clientHelloAndServerHello, 48);

                txtMasterSecret.Text = masterSecret.ToDisplayByteString();

                byte[] serverHelloAndClientHello = ByteUtilities.ConcatBytes(serverHelloRandom, clientHelloRandom);

                byte[] keyBlock = Prf10.GenerateBytes(masterSecret, txtKeyExpansionLabel.Text, serverHelloAndClientHello, 96);

                byte[] client_write_MAC_secret = new byte[16];
                byte[] server_write_MAC_secret = new byte[16];
                byte[] client_write_key = new byte[16];
                byte[] server_write_key = new byte[16];
                byte[] client_write_IV = new byte[16];
                byte[] server_write_IV = new byte[16];

                Buffer.BlockCopy(keyBlock, 0, client_write_MAC_secret, 0, 16);
                txtClientWriteMacKey.Text = client_write_MAC_secret.ToDisplayByteString();

                Buffer.BlockCopy(keyBlock, 16, server_write_MAC_secret, 0, 16);
                txtServerWriteMacKey.Text = server_write_MAC_secret.ToDisplayByteString();

                Buffer.BlockCopy(keyBlock, 32, client_write_key, 0, 16);
                txtClientWriteKey.Text = client_write_key.ToDisplayByteString();

                Buffer.BlockCopy(keyBlock, 48, server_write_key, 0, 16);
                txtServerWriteKey.Text = server_write_key.ToDisplayByteString();

                Buffer.BlockCopy(keyBlock, 64, client_write_IV, 0, 16);
                txtClientIV.Text = client_write_IV.ToDisplayByteString();

                Buffer.BlockCopy(keyBlock, 80, server_write_IV, 0, 16);
                txtServerIV.Text = server_write_IV.ToDisplayByteString();

                byte[] clientHello = txtClientHello.Text.FromWireshark();
                byte[] serverHello = txtServerHello.Text.FromWireshark();
                byte[] certificate = txtServerHelloCertificate.Text.FromWireshark();
                byte[] serverHelloDone = txtServerHelloDone.Text.FromWireshark();
                byte[] clientKeyExchangeEncrypted = txtClientKeyExchange.Text.FromWireshark();

                byte[] handshakeMessages = ByteUtilities.ConcatBytes(clientHello, serverHello, certificate, serverHelloDone, clientKeyExchangeEncrypted);
                txtHandshakeMessages.Text = handshakeMessages.ToDisplayByteString(16);

                var md5Handshake = Hasher.ComputeMD5(handshakeMessages);
                txtMd5HandshakeMessages.Text = md5Handshake.ToDisplayByteString();

                var sha1Handshake = Hasher.ComputeSHA1Hash(handshakeMessages);
                txtSha1HandshakeMessages.Text = sha1Handshake.ToDisplayByteString();

                byte[] clientVerifyData = Prf10.GenerateBytes(masterSecret, txtClientFinishedLabel.Text, ByteUtilities.ConcatBytes(md5Handshake, sha1Handshake), 12);
                txtClientFinishedVerifyData.Text = clientVerifyData.ToDisplayByteString();

                var clientFinishedHeaderBytes = txtClientFinishedHeader.Text.FromWireshark();
                var clientFinishedHash = Hasher.ComputeTlsMD5Hmac(client_write_MAC_secret, 0x16, 0, ByteUtilities.ConcatBytes(clientFinishedHeaderBytes, clientVerifyData));
                txtClientFinishedHmacMd5.Text = clientFinishedHash.ToDisplayByteString();
                var clientFinishedHeaderAndVerify = ByteUtilities.ConcatBytes(clientFinishedHeaderBytes, clientVerifyData);
                var clientFinishedDecrypted = ByteUtilities.ConcatBytes(clientFinishedHeaderBytes, clientVerifyData, clientFinishedHash);
                Arc4 clientWriteArc4 = new Arc4(client_write_key);
                var clientFinishedEncrypted = clientWriteArc4.Encrypt(clientFinishedDecrypted);                

                var expectedClientFinishedEncrypted = txtClientEncryptedFinishedMessage.Text.FromWireshark();
                Debug.Assert(ByteUtilities.AreEqual(expectedClientFinishedEncrypted, clientFinishedEncrypted));

                byte[] clientApplicationData = txtClientApplicationDataInput.Text.FromWireshark();            
                byte[] decryptedBytes = clientWriteArc4.Encrypt(clientApplicationData);
                byte[] plainTextBytes = new byte[decryptedBytes.Length - 16];
                Buffer.BlockCopy(decryptedBytes, 0, plainTextBytes, 0, plainTextBytes.Length);

                string plainText = ASCIIEncoding.ASCII.GetString(plainTextBytes);
                txtDecryptedClientApplicationData.Text = plainText;

                byte[] hmacClientBytesReceived = new byte[16];
                Buffer.BlockCopy(decryptedBytes, plainTextBytes.Length, hmacClientBytesReceived, 0, 16);
                txtClientApplicationDataHmac.Text = hmacClientBytesReceived.ToDisplayByteString();

                var hmacFirstClientPacket = Hasher.ComputeTlsMD5Hmac(client_write_MAC_secret, 23, 1, plainTextBytes);
                Debug.Assert(ByteUtilities.AreEqual(hmacFirstClientPacket, hmacClientBytesReceived));

                // get server reply
                var serverHandshakeMessages = ByteUtilities.ConcatBytes(handshakeMessages, clientFinishedHeaderAndVerify);
                var serverFinishedHeader = txtServerFinishedHeader.Text.FromWireshark();
                md5Handshake = Hasher.ComputeMD5(serverHandshakeMessages);
                sha1Handshake = Hasher.ComputeSHA1Hash(serverHandshakeMessages);
                var serverVerifyData = Prf10.GenerateBytes(masterSecret, txtServerFinishedLabel.Text, ByteUtilities.ConcatBytes(md5Handshake, sha1Handshake), 12);
                txtServerFinishedVerifyData.Text = serverVerifyData.ToDisplayByteString();
                var serverFirstHash = Hasher.ComputeTlsMD5Hmac(server_write_MAC_secret, 0x16, 0, ByteUtilities.ConcatBytes(serverFinishedHeader, serverVerifyData));
                txtServerFinishedHmacMd5.Text = serverFirstHash.ToDisplayByteString();

                var serverArc4 = new Arc4(server_write_key);

                var serverFinishedMessage = ByteUtilities.ConcatBytes(serverFinishedHeader, serverVerifyData, serverFirstHash);
                var encryptedServerFinishedMessage = serverArc4.Encrypt(serverFinishedMessage);

                Debug.Assert(ByteUtilities.AreEqual(encryptedServerFinishedMessage, txtServerEncryptedHandshakeMessage.Text.FromWireshark()));

                var serverApplicationDataBytes = txtServerApplicationDataInput.Text.FromWireshark();                
                var decryptedServerApplicationDataBytes = serverArc4.Encrypt(serverApplicationDataBytes);
                
                var serverPlainTextBytes = new byte[decryptedServerApplicationDataBytes.Length - 16];
                Buffer.BlockCopy(decryptedServerApplicationDataBytes, 0, serverPlainTextBytes, 0, serverPlainTextBytes.Length);

                var hmacServerFirstPacketReceived = new byte[16];
                Buffer.BlockCopy(decryptedServerApplicationDataBytes, serverPlainTextBytes.Length, hmacServerFirstPacketReceived, 0, 16);

                txtDecryptedServerApplicationData.Text = ASCIIEncoding.ASCII.GetString(serverPlainTextBytes);
                var hmacServerFirstPacketComputed = Hasher.ComputeTlsMD5Hmac(server_write_MAC_secret, 23, 1, serverPlainTextBytes);                
                txtServerApplicationDataHmac.Text = hmacServerFirstPacketComputed.ToDisplayByteString();

                Debug.Assert(ByteUtilities.AreEqual(hmacServerFirstPacketComputed, hmacServerFirstPacketComputed));
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error calculating derived handshake info: " + ex.Message);
            }
        }

        private void btnPrfGenerate_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] secretBytes = txtPrfSecretBytes.Text.FromWireshark();
                string prfLabel = txtPrfLabel.Text;
                byte[] seedBytes = txtPrfSeedBytes.Text.FromWireshark();
                int bytesToGenerate = (int)nudBytesToGenerate.Value;

                txtPrfAsciiLabelBytes.Text = prfLabel.ToAsciiBytes().ToDisplayByteString();
                byte[] prfBytes = Prf10.GenerateBytes(secretBytes, prfLabel, seedBytes, bytesToGenerate);
                txtPrfOutput.Text = prfBytes.ToDisplayByteString();
                txtPrfMD5Output.Text = Hasher.ComputeMD5(prfBytes).ToDisplayByteString();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error generating PRF: " + ex.Message);
            }
        }        

        private void btnGenerateHmac_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] keyBytes = txtHmacKeyString.Text.ToAsciiBytes();
                txtHmacKeyAsciiBytes.Text = keyBytes.ToDisplayByteString();

                byte[] dataBytes = txtHmacDataString.Text.ToAsciiBytes();
                txtHmacDataAsciiBytes.Text = dataBytes.ToDisplayByteString();

                const int blockSize = 64;
                Func<byte, byte[]> getPad = padByte => Enumerable.Range(1, blockSize).Select(n=>padByte).ToArray();

                // SHA-1
                                
                byte[] sha1Key = keyBytes.Length > blockSize ? Hasher.ComputeSHA1Hash(keyBytes) : keyBytes;

                byte[] sha1Opad = getPad(0x5c);
                txtHmacSha1Opad.Text = sha1Opad.ToDisplayByteString();

                byte[] sha1KeyXorOpad = sha1Key.Xor(sha1Opad);

                txtHmacSha1KeyXorOpad.Text = sha1KeyXorOpad.ToDisplayByteString();

                byte[] sha1Ipad = getPad(0x36);
                txtHmacSha1IpadBytes.Text = sha1Ipad.ToDisplayByteString();

                byte[] sha1KeyXorIpad = sha1Key.Xor(sha1Ipad);
                txtHmacSha1KeyXorIpad.Text = sha1KeyXorIpad.ToDisplayByteString();

                byte[] sha1TotalInnerToHash = ByteUtilities.ConcatBytes(sha1KeyXorIpad, dataBytes);
                byte[] sha1InnerHash = Hasher.ComputeSHA1Hash(sha1TotalInnerToHash);

                txtHmacSha1InnerHash.Text = sha1InnerHash.ToDisplayByteString();

                byte[] sha1Hmac = Hasher.ComputeSHA1Hash(ByteUtilities.ConcatBytes(sha1KeyXorOpad, sha1InnerHash));
                byte[] sha1ExpectedHmac = Hasher.ComputeSHA1Hmac(keyBytes, dataBytes);
                Debug.Assert(ByteUtilities.AreEqual(sha1ExpectedHmac, sha1Hmac));

                txtHmacSha1Result.Text = sha1Hmac.ToDisplayByteString();


                // MD5                
                              
                byte[] md5Key = keyBytes.Length > blockSize ? Hasher.ComputeMD5(keyBytes) : keyBytes;

                byte[] md5Opad = getPad(0x5c);
                txtHmacMd5Opad.Text = md5Opad.ToDisplayByteString();
                
                byte[] md5KeyXorOpad = md5Key.Xor(md5Opad);

                txtHmacMd5KeyXorOpad.Text = md5KeyXorOpad.ToDisplayByteString();

                byte[] md5Ipad = getPad(0x36);
                txtHmacMd5IpadBytes.Text = md5Ipad.ToDisplayByteString();

                byte[] md5KeyXorIpad = md5Key.Xor(md5Ipad);
                txtHmacMd5KeyXorIpad.Text = md5KeyXorIpad.ToDisplayByteString();

                byte[] md5TotalInnerToHash = ByteUtilities.ConcatBytes(md5KeyXorIpad, dataBytes);
                byte[] md5InnerHash = Hasher.ComputeMD5(md5TotalInnerToHash);

                txtHmacMd5InnerHash.Text = md5InnerHash.ToDisplayByteString();

                byte[] md5Hmac = Hasher.ComputeMD5(ByteUtilities.ConcatBytes(md5KeyXorOpad, md5InnerHash));
                byte[] md5ExpectedHmac = Hasher.ComputeMD5Hmac(keyBytes, dataBytes);
                Debug.Assert(ByteUtilities.AreEqual(md5ExpectedHmac, md5Hmac));

                txtHmacMd5Result.Text = md5Hmac.ToDisplayByteString();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message);
            }
        }

        private void btnCalculateCertificateInformation_Click(object sender, EventArgs e)
        {
            try
            {
                // Get moduli ahead of time since they'll be needed in a chained fashion
                byte[] amazonModulusBytes = txtAmazonModulus.Text.FromWireshark();
                BigInteger amazonModulus = new BigInteger(amazonModulusBytes);
                txtAmazonModulusBase10.Text = amazonModulus.ToDisplayString();
                byte[] amazonPublicExponentBytes = txtAmazonPublicExponent.Text.FromWireshark();


                byte[] verisignClass3SecureServerModulusBytes = txtVerisignClass3SecureServerModulus.Text.FromWireshark();
                BigInteger verisignClass3SecureServerModulus = new BigInteger(verisignClass3SecureServerModulusBytes);
                txtVerisignClass3SecureServerModulusBase10.Text = verisignClass3SecureServerModulus.ToDisplayString();
                byte[] verisignClass3SecureServerPublicExponentBytes = txtVerisignClass3SecureServerPublicExponent.Text.FromWireshark();

                byte[] verisignClass3PrimaryCertificationAuthorityModulusBytes = txtVerisignClass3PrimaryCertificationAuthorityModulus.Text.FromWireshark();
                BigInteger verisignClass3PrimaryCertificationAuthorityModulus = new BigInteger(verisignClass3PrimaryCertificationAuthorityModulusBytes);
                txtVerisignClass3PrimaryCertificationAuthorityModulusBase10.Text = verisignClass3PrimaryCertificationAuthorityModulus.ToDisplayString();
                byte[] verisignClass3PrimaryCertificationAuthorityPublicExponentBytes = txtVerisignClass3PrimaryCertificationAuthorityPublicExponent.Text.FromWireshark();

                byte[] amazonSignedCertificateBytes = txtAmazonSignatureValue.Text.FromWireshark();
                byte[] amazonDecryptedSignatureBytes = RsaUtilities.GetSignedOriginalValue(amazonSignedCertificateBytes, verisignClass3SecureServerPublicExponentBytes, verisignClass3SecureServerModulusBytes);
                txtAmazonDecryptedSignature.Text = amazonDecryptedSignatureBytes.ToDisplayByteString(16);

                const int sha1HashSize = 20; // bytes
                byte[] amazonHashValueBytes = amazonDecryptedSignatureBytes.SubBytes(amazonDecryptedSignatureBytes.Length - sha1HashSize);

                Debug.Assert(ByteUtilities.AreEqual(Hasher.ComputeSHA1Hash(txtAmazonSignedCertificate.Text.FromWireshark()), amazonHashValueBytes));
                
                txtAmazonHashValue.Text = amazonHashValueBytes.ToDisplayByteString();

                // For algorithm info, see http://tools.ietf.org/html/rfc3447#page-43
                const int algorithmIdSize = 15; // bytes
                byte[] amazonAlgorithmIdBytes = amazonDecryptedSignatureBytes.SubBytes(amazonDecryptedSignatureBytes.Length - sha1HashSize - algorithmIdSize, algorithmIdSize);
                txtAmazonHashAlgorithmId.Text = amazonAlgorithmIdBytes.ToDisplayByteString();
                                
                byte[] verisignClass3SecureServerSignatureValueBytes = txtVerisignClass3SecureServerSignatureValue.Text.FromWireshark();
                byte[] verisignClass3SecureServerDecryptedSignatureBytes = RsaUtilities.GetSignedOriginalValue(verisignClass3SecureServerSignatureValueBytes, verisignClass3PrimaryCertificationAuthorityPublicExponentBytes, verisignClass3PrimaryCertificationAuthorityModulusBytes);
                txtVerisignClass3SecureServerDecryptedSignature.Text = verisignClass3SecureServerDecryptedSignatureBytes.ToDisplayByteString(16);
                byte[] verisignClass3SecureServerHashValueBytes = verisignClass3SecureServerDecryptedSignatureBytes.SubBytes(verisignClass3SecureServerDecryptedSignatureBytes.Length - sha1HashSize);

                Debug.Assert(ByteUtilities.AreEqual(Hasher.ComputeSHA1Hash(txtVersignClass3SecureServerSignedCertificate.Text.FromWireshark()), verisignClass3SecureServerHashValueBytes));

                txtVerisignClass3SecureServerHashValue.Text = verisignClass3SecureServerHashValueBytes.ToDisplayByteString();
                byte[] verisignClass3SecureServerAlgorithmIdBytes = verisignClass3SecureServerDecryptedSignatureBytes.SubBytes(verisignClass3SecureServerDecryptedSignatureBytes.Length - sha1HashSize - algorithmIdSize, algorithmIdSize);
                txtVerisignClass3SecureServerHashAlgorithmId.Text = verisignClass3SecureServerAlgorithmIdBytes.ToDisplayByteString();

                byte[] verisignClass3PrimaryCertificationAuthoritySignatureValueBytes = txtVerisignClass3PrimaryCertificationAuthoritySignatureValue.Text.FromWireshark();
                byte[] verisignClass3PrimaryCertificationAuthorityDecryptedSignatureBytes = RsaUtilities.GetSignedOriginalValue(verisignClass3PrimaryCertificationAuthoritySignatureValueBytes, verisignClass3PrimaryCertificationAuthorityPublicExponentBytes, verisignClass3PrimaryCertificationAuthorityModulusBytes);
                txtVerisignClass3PrimaryCertificationAuthorityDecryptedSignature.Text = verisignClass3PrimaryCertificationAuthorityDecryptedSignatureBytes.ToDisplayByteString(16);
                
                const int md2HashSize = 16; // bytes
                int md2AlgorithmIdSize = algorithmIdSize + 3;
                byte[] verisignClass3PrimaryCertificationAuthorityHashValueBytes = verisignClass3SecureServerDecryptedSignatureBytes.SubBytes(verisignClass3SecureServerDecryptedSignatureBytes.Length - md2HashSize);
                txtVerisignClass3PrimaryCertificationAuthorityHashValue.Text = verisignClass3PrimaryCertificationAuthorityHashValueBytes.ToDisplayByteString();
                byte[] verisignClass3PrimaryCertificationAuthorityAlgorithmIdBytes = verisignClass3PrimaryCertificationAuthorityDecryptedSignatureBytes.SubBytes(verisignClass3PrimaryCertificationAuthorityDecryptedSignatureBytes.Length - md2HashSize - md2AlgorithmIdSize, md2AlgorithmIdSize);
                txtVerisignClass3PrimaryCertificationAuthorityHashAlgorithmId.Text = verisignClass3PrimaryCertificationAuthorityAlgorithmIdBytes.ToDisplayByteString();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message);
            }
        }
    }
}