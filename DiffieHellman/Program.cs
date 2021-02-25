using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DiffieHellman
{
    class Person1
    {
        public static byte[] Person1PublicKey;
        static void Main(string[] args)
        {
            Console.WriteLine("----------------------------------");
            Console.WriteLine("-WELCOME TO DIFFIE HELLMAN ENCRYPTION METHOD-");
            Console.WriteLine("----------------------------------");

            Helman();
        }

        private static void Helman()
        {
            Console.Write("Plase Enter Message to Encrypt : ");
            string text = Convert.ToString(Console.ReadLine());
            Console.WriteLine("----------------------------------");

            using (ECDiffieHellmanCng ecd = new ECDiffieHellmanCng())
            {
                ecd.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecd.HashAlgorithm = CngAlgorithm.Sha256;
                Person1PublicKey = ecd.PublicKey.ToByteArray();

                Person2 person2 = new Person2();

                CngKey k = CngKey.Import(person2.Person2PublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] senderKey = ecd.DeriveKeyMaterial(CngKey.Import(person2.Person2PublicKey, CngKeyBlobFormat.EccPublicBlob));
                Send(senderKey, text, out byte[] encryptedMessage, out byte[] IV);
                person2.Receive(encryptedMessage, IV);

            }
        }

        public static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] IV)
        {
            Console.WriteLine("Message Sending ... ");
            Console.WriteLine("----------------------------------");

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                IV = aes.IV;

                // Encrypt the message
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plainTextMessage = Encoding.UTF8.GetBytes(secretMessage);
                    cs.Write(plainTextMessage, 0, plainTextMessage.Length);
                    cs.Close();
                    encryptedMessage = ms.ToArray();

                }
            }
        }
    }


    public class Person2
    {
        public byte[] Person2PublicKey;
        private byte[] Key;

        public Person2()
        {
            using (ECDiffieHellmanCng ecd = new ECDiffieHellmanCng())
            {
                ecd.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecd.HashAlgorithm = CngAlgorithm.Sha256;
                Person2PublicKey = ecd.PublicKey.ToByteArray();
                Key = ecd.DeriveKeyMaterial(CngKey.Import(Person1.Person1PublicKey, CngKeyBlobFormat.EccPublicBlob));

            }

            Console.Write("Encrypted Version : ");

            foreach (byte b in Key)
            {
                Console.Write($"{b}, ");

            }
            Console.WriteLine("\n----------------------------------");

        }

        public void Receive(byte[] encryptedMessage, byte[] IV)
        {
            Console.WriteLine("Converting ... ");
            Console.WriteLine("----------------------------------");

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = Key;
                aes.IV = IV;

                // Decrypt and show the message
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();

                        string message = Encoding.UTF8.GetString(ms.ToArray());
                        Console.Write("Resolved : ");
                        Console.Write(message);

                    }
                }
                Console.ReadKey();



            }
        }
    }
}
