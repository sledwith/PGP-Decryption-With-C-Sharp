using SPL.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;


namespace PGPSample
{
    public class Decrypt
    {
        #region Private Properties

        /// <summary>
        /// You could put your passPhrase in the app.config file, but I wouldn't suggest it. The pass
        /// phrase is required for someone be be the "digital" you, so keep it safe!
        /// </summary>
        private string passPhrase
        {
            get { return "This is my passphrase. There are many like it, but this one is mine."; }
        }

        /// <summary>
        /// The path to your private key ring - stored in the app.config file.
        /// </summary>
        private string secretKeyRingPath
        {
            get { return System.Configuration.ConfigurationSettings.AppSettings["secureKeyRing"]; }
        }

        /// <summary>
        /// The path to your public key ring - stored in the app.config file.
        /// </summary>
        private string publicKeyRingPath
        {
            get { return System.Configuration.ConfigurationSettings.AppSettings["publicKeyRing"]; }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// This method trims the last extension from the file you passed in.
        /// </summary>
        /// <param name="encryptedFileName">
        /// Full path and file name for the ecrypted file. Expecting something like:
        /// C:\Data\Files\SuperSecret\Secret\Squirrel.txt.gpg
        /// </param>
        /// <returns>
        /// Returns the path and name of the output file. Example:
        /// C:\Data\Files\SuperSecret\Secret\Squirrel.txt
        /// </returns>
        private string extractOutputFileName(string encryptedFileName)
        {
            return encryptedFileName.Substring(0, encryptedFileName.LastIndexOf('.'));
        }

        /// <summary>
        /// Implements the SPL.Crypto DecryptAndVerify routine.
        /// </summary>
        /// <param name="encryptedFileName">Full path and file name for the ecrypted file.</param>
        /// <returns>True / False. True if the file was decrypted and written successfully.</returns>
        private bool decryptInputFile(string encryptedFileName)
        {
            bool returnCode;
            string outputFile = extractOutputFileName(encryptedFileName);

            try
            {
                SPL.Crypto.PgpEncryptionKeys keys = new PgpEncryptionKeys(publicKeyRingPath, secretKeyRingPath, passPhrase);
                PgpDecrypt decryptor = new PgpDecrypt(keys);
                Stream encryptedStream = new StreamReader(encryptedFileName).BaseStream;
                decryptor.DecryptAndVerify(encryptedStream, outputFile);
                returnCode = true;
            }
            catch (Exception)
            {
                // If there was an error, we're going to eat it and just let the user know we failed.
                returnCode = false;
            }

            return returnCode;
        }

        #endregion

        #region Public Methods

        /// <summary>
        ///     Will decrypt the file and save it in the same location with out the .gpg extension.
        /// </summary>
        /// <param name="encryptedFilePath">Complete path to the encrypted file with a .gpg extension.</param>
        /// <returns>True if the file was decrypted successfully.</returns>
        public bool DecryptFile(string encryptedFilePath)
        {
            return decryptInputFile(encryptedFilePath);
        }

        #endregion
    }
}
