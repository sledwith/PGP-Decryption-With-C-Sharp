using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.IO;

/// Code is provided as-is, as-written. I'm not an expert in cryptography, and I don't plan
/// on releasing updates. Please review prior to using in anything critical.
/// Steve Ledwith - steve@ledwith.org - http://ledwith.org
/// Released under GPLv3 - Please contact me if you have any questions.
namespace SPL.Crypto
{
    /// <summary>
    /// Wrapper around Bouncy Castle OpenPGP library.
    /// Bouncy documentation can be found here: http://www.bouncycastle.org/docs/pgdocs1.6/index.html
    /// Code from: http://blogs.microsoft.co.il/blogs/kim/archive/2009/01/23/pgp-zip-encrypted-files-with-c.aspx
    /// with some very minor changes.
    /// </summary>
    public class PgpEncrypt
    {
        #region Private Variables
        
        private PgpEncryptionKeys mEncryptionKeys;
        private const int bufferSize = 0x10000; // should always be power of 2 
        
        #endregion

        #region Public Methods
        /// <summary>
        /// Instantiate a new PgpEncrypt class with initialized PgpEncryptionKeys.
        /// </summary>
        /// <param name="encryptionKeys"></param>
        /// <exception cref="ArgumentNullException">encryptionKeys is null</exception>
        public PgpEncrypt(PgpEncryptionKeys encryptionKeys)
        {
            if (encryptionKeys == null)
            {
                throw new ArgumentNullException("encryptionKeys", "encryptionKeys is null.");
            }

            mEncryptionKeys = encryptionKeys;
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// write the encrypted content to outputStream.
        /// </summary>
        /// <param name="outputStream">
        ///     The stream that will contain the encrypted data when this method returns.
        /// </param>
        /// <param name="fileName">FileInfo of the file to encrypt</param>
        public void EncryptAndSign(Stream outputStream, FileInfo unencryptedFileInfo)
        {
            if (outputStream == null)
            {
                throw new ArgumentNullException("outputStream", "outputStream is null.");
            }
            if (unencryptedFileInfo == null)
            {
                throw new ArgumentNullException("unencryptedFileInfo", "unencryptedFileInfo is null.");
            }
            if (!File.Exists(unencryptedFileInfo.FullName))
            {
                throw new ArgumentException("File to encrypt not found.");
            }

            using (Stream encryptedOut = chainEncryptedOut(outputStream))
            {
                using (Stream compressedOut = chainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = initSignatureGenerator(compressedOut);
                    using (Stream literalOut = chainLiteralOut(compressedOut, unencryptedFileInfo))
                    {
                        using (FileStream inputFile = unencryptedFileInfo.OpenRead())
                        {
                            writeOutputAndSign(compressedOut, literalOut, inputFile, signatureGenerator);
                        }
                    }
                }
            }
        }

        #endregion

        #region Private Methods
        private static void writeOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFile, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[bufferSize];

            while ((length = inputFile.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOut);
        }

        private Stream chainEncryptedOut(Stream outputStream)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes, new SecureRandom());
            encryptedDataGenerator.AddMethod(mEncryptionKeys.PublicKey);

            return encryptedDataGenerator.Open(outputStream, new byte[bufferSize]);
        }

        private static Stream chainCompressedOut(Stream encryptedOut)
        {
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            return compressedDataGenerator.Open(encryptedOut);
        }

        private static Stream chainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, PgpLiteralData.Binary, file);
        }

        private PgpSignatureGenerator initSignatureGenerator(Stream compressedOut)
        {
            const bool IsCritical = false;
            const bool IsNested = false;

            PublicKeyAlgorithmTag tag = mEncryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, mEncryptionKeys.PrivateKey);

            foreach (string userId in mEncryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(IsCritical, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());

                // Just the first one!
                break;
            }

            pgpSignatureGenerator.GenerateOnePassVersion(IsNested).Encode(compressedOut);
            return pgpSignatureGenerator;
        }

        #endregion
    }
}
