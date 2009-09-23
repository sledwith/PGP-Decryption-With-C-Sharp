using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PGPSample
{
    class Program
    {
        static void Main(string[] args)
        {
            PGPSample.Program app = new Program();
            app.decryptInputFile();
            app.clickToContinue();
        }

        #region Private Properties

        private string getSourceFile
        {
            get { return System.Configuration.ConfigurationSettings.AppSettings["encryptedSourceFile"]; }
        }

        private string getDestinationFile
        {
            get { return trimEncryptedFileName(getSourceFile); }
        }

        #endregion

        #region Private Methods

        private void clickToContinue()
        {
            Console.WriteLine("Press any key to continue ... ");
            Console.ReadLine();
        }

        private string trimEncryptedFileName(string fileName)
        {
            return fileName.Substring(0, fileName.LastIndexOf('.'));
        }

        private void updateStatusMessage(string message)
        {
            Console.WriteLine(string.Concat(DateTime.Now.ToShortTimeString(), ": ", message));
        }

        private void decryptInputFile()
        {
            bool success = false;

            string source = getSourceFile;
            updateStatusMessage(string.Concat("Source: ", source));

            string destination = getDestinationFile;
            updateStatusMessage(string.Concat("Destination: ", destination));

            Decrypt decryptor = new Decrypt();
            updateStatusMessage("Decrypting Source File ... ");
            
            success = decryptor.DecryptFile(source);
            updateStatusMessage("Job Finished!");

            if (!success)
            {
                updateStatusMessage("Failed - check the file and your settings.");
                throw new DecoderFallbackException("Could not decode input file.");
            }

            updateStatusMessage("File successfully decrypted.");
            return;
        }

        #endregion
    }
}
