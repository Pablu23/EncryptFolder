using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EncryptFolder
{
    public static class Program
    {
        private static string _workDir = Directory.GetCurrentDirectory();
        private static string _encryptFolder = Path.Combine(_workDir, "private");
        private static string _password = "";

        public static void Main()
        {
            if (Directory.Exists(_encryptFolder))
            {
                MenuDecrypt();
            }
            else
            {
                MenuEncrypt();
            }
        }

        private static void MenuDecrypt()
        {
            Console.Write("Enter Password: ");
            string? password = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("No password was Input.\nClosing Program...");
                Environment.Exit(0);
            }
            _password = password;
            StartDecryptProc();
        }

        private static void MenuEncrypt()
        {
            var files = Directory.GetFiles(_workDir).ToList();

            // Get Path of Executable
            // Exe File is supposed to be in the same Folder as the Files that should get encrypted,
            // but should obviously not be encrypted itself
            string? execPath = Environment.ProcessPath;
            string? dllPath = Assembly.GetEntryAssembly()?.Location;

            // If dll and or exe Path are in the files List, remove them.
            // If not remove all exe and dll files for safety
            if (!string.IsNullOrWhiteSpace(dllPath))
                files.RemoveAll(x => x == dllPath);
            if (string.IsNullOrWhiteSpace(execPath))
                files.RemoveAll(f => Path.GetExtension(f) == "exe" || Path.GetExtension(f) == "dll");
            else
                files.RemoveAll(x => x == execPath);

            foreach (string file in files)
            {
                Console.WriteLine(file);
            }

            Console.WriteLine("Are you sure you want to Encrypt these Files?\n[Y]es\n[N]o");
            string? input = Console.ReadLine();
            switch (input?.ToLower())
            {
                case "y" or "yes" or "j":
                    break;

                case "n" or "no":
                    Console.WriteLine("Exiting...");
                    Environment.Exit(0);
                    break;

                default:
                    Console.WriteLine("Wrong Input.\nClosing Program...");
                    Environment.Exit(0);
                    break;
            }

            Console.Write("Enter Password: ");
            string? password = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("No password was Input.\nClosing Program...");
                Environment.Exit(0);
            }
            _password = password;
            StartEncryptProc(files.ToArray());
        }

        private static void StartEncryptProc(string[] files)
        {
            // Creates private Folder
            Directory.CreateDirectory(_encryptFolder);

            // Creates List for tasks that are going to be run
            // Every file has its own Task
            var tasks = new List<Task>();

            for (int i = 0; i < files.Length; i++)
            {
                // Because of a racing condition and scoping issues the variables need to be set again here 
                // in order to work correctly
                string file = files[i];
                int index = i;

                // Run the Encrypt Process and add the running task to the tasks list
                tasks.Add(Task.Run(async () => await EncryptProc(file, index)));
            }

            try
            {
                var cancel = new CancellationTokenSource();
                Task.Run(() => UpdateConsole(cancel.Token));

                // Wait for all Tasks to complete
                Task.WaitAll(tasks.ToArray());

                // Cancel the UpdateConsole
                cancel.Cancel();
            }
            catch (AggregateException ex)
            {
                foreach (var inner in ex.InnerExceptions)
                {
                    Console.WriteLine($"Caught AggregateException in Task: " + inner.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Caught Exception in Main: " + ex.Message);
            }
        }

        private static Task EncryptProc(string path, int index)
        {
            // Obfuscate filename and add extension .enc
            string fileName = $"{index}.enc";

            // Create Path in the Private folder for storing of file
            string newPath = Path.Combine(_encryptFolder, fileName);

            // Creates 128 Bit Key from password
            // And retrieves random Salt used for it
            byte[] pwd = CreateKey(_password, out byte[] salt);

            var fileInfo = new FileInfo(path);

            bool withInfo = false;

            if (fileInfo.Length >= 30_000_000)
            {
                withInfo = true;
            }

            byte[] pwdHash = CreateHash(pwd);

            // Encrypt the File
            EncryptFile(path, newPath, pwd, salt, pwdHash, withInfo);

            // Delete the Unencrypted file
            File.Delete(path);

            return Task.CompletedTask;
        }

        private static void EncryptFile(string path, string outFile, byte[] key, byte[] salt, byte[] pwdHash, bool withInfo)
        {
            // Setup AES
            var aes = Aes.Create();
            aes.Key = key;

            // Create Encryptor with the Key and the AES Genereratev IV
            var transform = aes.CreateEncryptor(key, aes.IV);

            // Gets IV Length in bit
            int lIv = aes.IV.Length;
            byte[] lenIV = BitConverter.GetBytes(lIv);

            // Encrypt the Filename and get Length of Bytes
            string fileName = Path.GetFileName(path);

            byte[] name = EncryptString(key, aes.IV, fileName);
            int lName = name.Length;
            byte[] lenName = BitConverter.GetBytes(lName);

            // Gets Salt Length
            int lSalt = salt.Length;
            byte[] lenSalt = BitConverter.GetBytes(lSalt);

            // Gets PwdHash Length
            int lHash = pwdHash.Length;
            byte[] lenHash = BitConverter.GetBytes(lHash);

            using (var outFs = new FileStream(outFile, FileMode.Create))
            {
                /*
                 * 0 - 3 = Byte IV Length
                 * 4 - 7 = Byte Name Length
                 * 8 - 11 = Salt Length
                 * 12 - 15 = Hash Length
                 * 16 - IV Length = IV
                 * IV Length - Name Length = Name Obfuscated
                 * Name Length - Salt Length = Salt
                 * Salt Length - Hash Length = Hash
                 */

                // Write the IV Length to Header
                outFs.Write(lenIV, 0, 4);
                // Write Filename Length to Header
                outFs.Write(lenName, 0, 4);
                // Write Salt Length to Header
                outFs.Write(lenSalt, 0, 4);
                // Write Hash Length to Header
                outFs.Write(lenHash, 0, 4);

                // After IV Length Bit
                // Write the IV itself
                outFs.Write(aes.IV, 0, lIv);
                // Write the Filename (Encrypted)
                outFs.Write(name, 0, lName);
                // Write the Password Salt
                outFs.Write(salt, 0, lSalt);
                // Write teh Password Hash
                outFs.Write(pwdHash, 0, lHash);

                using (var outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                {
                    int count;
                    int offset = 0;

                    // BlockSizeBytes is arbitrary size
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];

                    using (var inFs = new FileStream(path, FileMode.Open))
                    {
                        // Go through every ByteBlock in File
                        do
                        {
                            long size = inFs.Length;

                            // Read bytes into data Array and set count to how many bytes were actually read
                            count = inFs.Read(data, 0, blockSizeBytes);

                            offset += count;

                            if (withInfo)
                            {
                                Info.AddOrUpdate(fileName, new Info() { BytesSize = size, BytesRead = offset, NewMessage = true }, (_, inf) =>
                                {
                                    inf.BytesRead = offset;
                                    inf.NewMessage = true;
                                    return inf;
                                });
                            }

                            // Encrypt bytes and Write it to new File
                            outStreamEncrypted.Write(data, 0, count);

                            // As long as there are more bytes to be read
                        } while (count > 0);
                    }
                    // Needed, but dont know what it does
                    outStreamEncrypted.FlushFinalBlock();
                }
            }
        }

        private static void StartDecryptProc()
        {
            // Create task List
            var tasks = new List<Task>();

            // Get the remaining encrypted Files
            var files = Directory.GetFiles(_encryptFolder).ToList();
            files.RemoveAll(f => Path.GetExtension(f) != ".enc");

            // Foreach encrypted File start a Task which decrypts that file
            foreach (string file in files)
            {
                // Because of a racing condition and scoping issues the variable needs to be set again here
                // in order to work correctly
                string path = file;
                tasks.Add(Task.Run(async () => await DecryptProc(path)));
            }

            try
            {
                var cancel = new CancellationTokenSource();
                Task.Run(() => UpdateConsole(cancel.Token));

                // Wait for all Tasks to complete
                Task.WaitAll(tasks.ToArray());

                cancel.Cancel();

                // Delete the now unused Folder
                Directory.Delete(_encryptFolder, false);
            }
            catch (AggregateException ex)
            {
                foreach (var inner in ex.InnerExceptions)
                {
                    Console.WriteLine($"Caught AggregateException in Task: " + inner.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Caught Exception in Main: " + ex.Message);
            }
        }

        private static Task DecryptProc(string path)
        {
            var fileInfo = new FileInfo(path);

            bool withInfo = false;

            if (fileInfo.Length >= 30_000_000)
            {
                withInfo = true;
            }

            // Create shared FileStream
            using (var fs = new FileStream(path, FileMode.Open))
            {
                // Get Header Metadata and Header Length
                (int headerLen, int ivLen, int nameLen, int saltLen, int hashLen) = GetFileHeader(fs);
                
                // Get Header Data and Point of where the Cipher starts
                (int startCipher, byte[] iv, byte[] name, byte[] salt, byte[] hash) = GetHeaderData(fs, headerLen, ivLen, nameLen, saltLen, hashLen);
                
                // Create 128 Bit (16 Byte) Key with Password and Salt
                byte[] key = CreateKey(_password, salt);

                byte[] generatedHash = CreateHash(key);

                if (!generatedHash.SequenceEqual(hash))
                    throw new Exception("Password was incorrect");

                // Decrypt the Filename
                string fileName = DecryptString(key, iv, name);
                // Create Output path
                string outFile = Path.Combine(_workDir, fileName);

                if (File.Exists(outFile))
                {
                    outFile = Path.Combine(_workDir, Path.GetRandomFileName());
                    outFile = Path.ChangeExtension(outFile, Path.GetExtension(fileName));
                }

                // Decrypt File to output Path
                DecryptFile(fs, outFile, startCipher, iv, key, withInfo);
            }

            // Delete the Encrypted File
            File.Delete(path);

            return Task.CompletedTask;
        }

        private static (int headerLen, int ivLen, int nameLen, int saltLen, int hashLen) GetFileHeader(FileStream inFs)
        {
            // lIV + lName + lSalt + lHash = 16
            int headerLen = 16;

            byte[] lIV = new byte[4];
            byte[] lName = new byte[4];
            byte[] lSalt = new byte[4];
            byte[] lHash = new byte[4];

            // Read IV Length
            inFs.Seek(0, SeekOrigin.Begin);
            inFs.Read(lIV, 0, 3);

            // Read Filename Length
            inFs.Seek(4, SeekOrigin.Begin);
            inFs.Read(lName, 0, 3);

            // Read Salt Length
            inFs.Seek(8, SeekOrigin.Begin);
            inFs.Read(lSalt, 0, 3);

            inFs.Seek(12, SeekOrigin.Begin);
            inFs.Read(lHash, 0, 3);

            // Convert Byte to int Length
            int ivLen = BitConverter.ToInt32(lIV, 0);
            int nameLen = BitConverter.ToInt32(lName, 0);
            int saltLen = BitConverter.ToInt32(lSalt, 0);
            int hashLen = BitConverter.ToInt32(lHash, 0);

            return (headerLen, ivLen, nameLen, saltLen, hashLen);
        }

        private static (int startCipher, byte[] iv, byte[] name, byte[] salt, byte[] pwdHash) GetHeaderData(FileStream inFs, int headerLen, int ivLen, int nameLen, int saltLen, int hashLen)
        {
            // Store IV
            byte[] iv = new byte[ivLen];
            inFs.Seek(headerLen, SeekOrigin.Begin);
            inFs.Read(iv, 0, ivLen);

            // Store Filename
            byte[] name = new byte[nameLen];
            inFs.Seek(headerLen + ivLen, SeekOrigin.Begin);
            inFs.Read(name, 0, nameLen);

            // Store Salt
            byte[] salt = new byte[saltLen];
            inFs.Seek(headerLen + ivLen + nameLen, SeekOrigin.Begin);
            inFs.Read(salt, 0, saltLen);

            byte[] hash = new byte[hashLen];
            inFs.Seek(headerLen + ivLen + nameLen + saltLen, SeekOrigin.Begin);
            inFs.Read(hash, 0, hashLen);

            // Data starts after Header and Header Data
            int startCipher = nameLen + ivLen + saltLen + hashLen + headerLen;
            return (startCipher, iv, name, salt, hash);
        }

        private static void DecryptFile(FileStream inFs, string outFile, int startCipher, byte[] iv, byte[] key, bool withInfo)
        {
            // Setup Aes
            using var aes = Aes.Create();
            aes.Key = key;
            //aes.Padding = PaddingMode.PKCS7;

            // Create Decryptor with the Key and the IV
            var transform = aes.CreateDecryptor(key, iv);

            string name = Path.GetFileName(inFs.Name);
            long size = inFs.Length;

            using var outFs = new FileStream(outFile, FileMode.CreateNew);
            using var outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write);

            int count;

            int overall = 0;

            // Arbitrary Size
            int blockSizeBytes = aes.BlockSize / 8;
            byte[] data = new byte[blockSizeBytes];

            // Set Stream position to starting Data Position
            inFs.Seek(startCipher, SeekOrigin.Begin);
            do
            {
                // Read Bytes into Data array and get read bytes
                count = inFs.Read(data, 0, blockSizeBytes);

                overall += count;

                if (withInfo)
                {
                    Info.AddOrUpdate(name, new Info() { BytesSize = size, BytesRead = overall, NewMessage = true }, (_, inf) =>
                    {
                        inf.BytesRead = overall;
                        inf.NewMessage = true;
                        return inf;
                    });
                }

                // Decrypts Bytes and writes them to the output file
                outStreamDecrypted.Write(data, 0, count);

                // As long as there are more Bytes to read
            } while (count > 0);

            // Dont know what this does but its needed
            outStreamDecrypted.FlushFinalBlock();
        }

        private static byte[] EncryptString(byte[] key, byte[] iv, string input)
        {
            if (input == null || input.Length <= 0)
                throw new ArgumentNullException(nameof(input));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));

            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create an encryptor to perform the stream transform.
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using var msEncrypt = new MemoryStream();
                using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    //Write all data to the stream.
                    swEncrypt.Write(input);
                }
                encrypted = msEncrypt.ToArray();
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        private static string DecryptString(byte[] key, byte[] iv, byte[] input)
        {
            if (input == null || input.Length <= 0)
                throw new ArgumentNullException(nameof(input));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));

            // Declare the string used to hold
            // the decrypted text.
            string plaintext;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using MemoryStream msDecrypt = new MemoryStream(input);
                using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    // Read the decrypted bytes from the decrypting stream
                    // and place them in a string.
                    plaintext = srDecrypt.ReadToEnd();
                }
            }

            return plaintext;
        }

        private static byte[] CreateHash(byte[] pwd)
        {
            using var hash = SHA256.Create();
            return hash.ComputeHash(pwd);
        }

        private static byte[] GetSalt(int maximumSaltLength)
        {
            return RandomNumberGenerator.GetBytes(maximumSaltLength);
        }

        private const int Iterations = 300;

        private static byte[] CreateKey(string password, out byte[] salt, int keyBytes = 16)
        {
            salt = GetSalt(32);
            var keyGenerator = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }

        private static byte[] CreateKey(string password, byte[] salt, int keyBytes = 16)
        {
            var keyGenerator = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }

        private static readonly ConcurrentDictionary<string, Info> Info = new ConcurrentDictionary<string, Info>();

        private static Task UpdateConsole(CancellationToken token)
        {
            (int _, int top) = Console.GetCursorPosition();

            var mapping = new Dictionary<string, int>();
            int highest = 0;

            while (true)
            {
                if (token.IsCancellationRequested)
                    return Task.CompletedTask;

                Thread.Sleep(1000);
                foreach ((string? key, var value) in Info)
                {
                    if (token.IsCancellationRequested)
                        return Task.CompletedTask;
                    
                    if (!mapping.ContainsKey(key))
                        mapping.Add(key, highest += 1);
                    
                    if (value.NewMessage)
                    {
                        double percent = (double) value.BytesRead / (double) value.BytesSize;
                        percent *= 100;

                        percent = Math.Round(percent, 2);

                        Console.SetCursorPosition(0, top + mapping[key]);
                        Console.WriteLine("[INFO] File {0,-30} {1,-5} % / 100 %", key, percent);
                        value.NewMessage = false;
                    }
                }
            }
        }
    }

    public class Info
    {
        public long BytesSize { get; set; }
        public int BytesRead { get; set; }
        public bool NewMessage { get; set; }
    }
}