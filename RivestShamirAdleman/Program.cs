using System;
using System.Security.Cryptography;
using System.Text;

namespace RivestShamirAdleman
{
    class Program
    {
        private static RSAParameters publicKey;
        private static RSAParameters privateKey;
        static void Main(string[] args)
        {
            Console.WriteLine("----------------------------------");
            Console.WriteLine("-WELCOME TO RSA ENCRYPTION METHOD-");
            Console.WriteLine("----------------------------------");
            Console.Write("Plase Enter Message to Encrypt : ");
            string text = Convert.ToString(Console.ReadLine());
            Console.WriteLine("----------------------------------");
            RSA(text);

 
        }

        private static void RSA(string msg)
        {
            createKey();
            byte[] encrypt = Encrypt(Encoding.UTF8.GetBytes(msg));
            byte[] decrypt = Decrypt(encrypt);

            Console.WriteLine("Your Message :" + msg);
            Console.WriteLine("----------------------------------");
            Console.WriteLine("Encrypted Version :" + BitConverter.ToString(encrypt).Replace("-", ""));
            Console.WriteLine("----------------------------------");
            Console.WriteLine("Resolved :" + Encoding.UTF8.GetString(decrypt));
            Console.WriteLine("----------------------------------");
            Console.ReadKey();
        }

        static byte[] Decrypt(byte[] input)
        {
            byte[] resolve;
            using (var rsa = new RSACryptoServiceProvider(512))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
                resolve = rsa.Decrypt(input, true);
            }
            return resolve;
        }

        static byte[] Encrypt(byte[] input)
        {
            byte[] sifrele;
            using (var rsa = new RSACryptoServiceProvider(512))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(publicKey);
                sifrele = rsa.Encrypt(input, true);
            }
            return sifrele;
        }

        static void createKey()
        {
            using (var rsa = new RSACryptoServiceProvider(512))
            {
                rsa.PersistKeyInCsp = false;
                publicKey = rsa.ExportParameters(false);
                privateKey = rsa.ExportParameters(true);
            }
        }
    }
}
