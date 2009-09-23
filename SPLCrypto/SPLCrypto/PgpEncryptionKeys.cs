using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;
using System.Linq;
using System.Text;

/// Code is provided as-is, as-written. I'm not an expert in cryptography, and I don't plan
/// on releasing updates. Please review prior to using in anything critical.
/// Steve Ledwith - steve@ledwith.org - http://ledwith.org
/// Released under GPLv3 - Please contact me if you have any questions.
namespace SPL.Crypto
{
    public class PgpEncryptionKeys
    {
        #region Public Methods
        public PgpPublicKey PublicKey { get; private set; }
        public PgpPrivateKey PrivateKey { get; private set; }
        public PgpSecretKey SecretKey { get; private set; }

        /// <summary>
        /// Initializes a new instance of the EncryptionKeys class.
        /// Two keys are required to encrypt and sign data. Your private key and the recipients public key.
        /// The data is encrypted with the recipients public key and signed with your private key.
        /// </summary>
        /// <param name="publicKeyPath">The key used to encrypt the data</param>
        /// <param name="privateKeyPath">The key used to sign the data.</param>
        /// <param name="passPhrase">The (your) password required to access the private key</param>
        /// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>
        public PgpEncryptionKeys(string publicKeyPath, string privateKeyPath, string passPhrase)
        {
            if (!File.Exists(publicKeyPath))
            {
                throw new ArgumentException("Public key file not found.", "publicKeyPath");
            }
            if (!File.Exists(privateKeyPath))
            {
                throw new ArgumentException("Private key file not found.", "privateKeyPath");
            }
            if (String.IsNullOrEmpty(passPhrase))
            {
                throw new ArgumentException("passPhrase is null or empty.", "passPhrase");
            }

            PublicKey = readPublicKey(publicKeyPath);
            SecretKey = readSecretKey(privateKeyPath);
            PrivateKey = readPrivateKey(passPhrase);
        }

        #endregion

        #region Private Methods

        #region Secret Key

        private PgpSecretKey readSecretKey(string privateKeyPath)
        {
            using (Stream keyIn = File.OpenRead(privateKeyPath))
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
                {
                    PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                    PgpSecretKey foundKey = getFirstSecretKey(secretKeyRingBundle);

                    if (foundKey != null)
                    {
                        return foundKey;
                    }
                }
            }
            throw new ArgumentException("Can't find signing key in key ring.");
        }

        /// <summary>
        /// Return the first key we can use to encrypt.
        /// Note: A file can contain multiple keys (stored in "key rings")
        /// </summary>
        private PgpSecretKey getFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                // Note: You may need to use something other than the first key
                //  in your key ring. Keep that in mind. 
                // ex: .Where(k => !k.IsSigningKey)
                PgpSecretKey key = kRing.GetSecretKeys()
                    .Cast<PgpSecretKey>()
                    //.Where(k => k.IsSigningKey)
                    .Where(k => !k.IsSigningKey)
                    .FirstOrDefault();

                if (key != null)
                {
                    return key;
                }
            }

            return null;
        }

        #endregion

        #region Public Key

        private PgpPublicKey readPublicKey(string publicKeyPath)
        {
            using (Stream keyIn = File.OpenRead(publicKeyPath))
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
                {
                    try
                    {
                        PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                        PgpPublicKey foundKey = getFirstPublicKey(publicKeyRingBundle);

                        if (foundKey != null)
                        {
                            return foundKey;
                        }
                    }
                    catch (Exception)
                    {
                        throw new ArgumentException("There was a problem with the public key ring.");
                    }
                }
            }
            throw new ArgumentException("No encryption key found in public key ring.");
        }

        private PgpPublicKey getFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {
                PgpPublicKey key = kRing.GetPublicKeys()
                    .Cast<PgpPublicKey>()
                    .Where(k => k.IsEncryptionKey)
                    .FirstOrDefault();

                if (key != null)
                {
                    return key;
                }
            }

            return null;
        }

        #endregion

        #region Private Key

        private PgpPrivateKey readPrivateKey(string passPhrase)
        {
            PgpPrivateKey privateKey = SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());

            if (privateKey != null)
            {
                return privateKey;
            }

            throw new ArgumentException("No private key found in secret key.");
        }

        #endregion

        #endregion
    }
}
