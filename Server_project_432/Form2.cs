// SERVER-1

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows.Forms;

using System.Security.Cryptography;
using System.IO;
using System.Linq;

namespace Server_project_432
{
    public partial class Form2 : Form
    {
        bool terminating = false;
        bool listening = false;

        Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp); // THAT SERVER'S SOCKET
        Socket server_2_socket; // SERVER-2'S SOCKET
        Socket remoteSocket; // MASTER SERVER SOCKET


        bool master_connected = false;
        bool server2_connected = false;
        bool server2_master_connected = false;

        List<Socket> socketList = new List<Socket>();
        List<string> connectionTypeList = new List<string>(); // store the type of the connected socket (client/server1/server2);

        List<Byte[]> server_2SessionKeys = new List<Byte[]>(); // list of session keys that distributed to servers.
        List<byte[]> not_replicated_files = new List<byte[]>(); // store recieved files when all servers are not connected
        List<string> not_replicated_file_names = new List<string>(); // store recieved file names when all servers are not connected


        string server1_pub_prv;
        string masterServer_public;
        string server2_public;

        byte[] AES_128_key_master = new byte[16];
        byte[] AES_128_IV_master = new byte[16];
        byte[] AES_128_HMAC_master = new byte[16];

        byte[] AES_128_key_server_2 = new byte[16];
        byte[] AES_128_IV_server_2 = new byte[16];
        byte[] AES_128_HMAC_server_2 = new byte[16];


        bool distributeFile(Socket socket, byte[] file_data, string file_name, string owner, string reciever)
        {
            byte[] AES_key = new byte[16];
            byte[] AES_IV = new byte[16];
            byte[] HMAC = new byte[16];

            if (reciever == "master_server")
            {
                AES_key = AES_128_key_master;
                AES_IV = AES_128_IV_master;
                HMAC = AES_128_HMAC_master;
            }
            else
            {
                AES_key = AES_128_key_server_2;
                AES_IV = AES_128_IV_server_2;
                HMAC = AES_128_HMAC_server_2;
            }
            byte[] message = Encoding.Default.GetBytes("File_Replication");
            socket.Send(message);

            //Thread.Sleep(300);

            //message = Encoding.Default.GetBytes(owner);
            //socket.Send(message);

            //Thread.Sleep(500);

            byte[] file_name_byte = Encoding.Default.GetBytes(file_name);

            // generating hmac for file/filename and sending to the reciever
            byte[] HMAC_file = applyHMACwithSHA256(file_data, HMAC);
            byte[] HMAC_file_name = applyHMACwithSHA256(file_name_byte, HMAC);

            string HMAC_file_hex = generateHexStringFromByteArray(HMAC_file);
            string HMAC_file_name_hex = generateHexStringFromByteArray(HMAC_file_name);
            string hmac_message_string = HMAC_file_name_hex + "::::::::::" + HMAC_file_hex;
            byte[] hmac_messages = Encoding.Default.GetBytes(hmac_message_string);
            //socket.Send(hmac_messages);

            //Thread.Sleep(300);
            //encrypting file and file name 
            byte[] encrypted_file = encryptWithAES128(file_data, AES_key, AES_IV);
            byte[] encrypted_file_name = encryptWithAES128(file_name_byte, AES_key, AES_IV);
            //socket.Send(file_name_byte);

            List<byte[]> encrypted_message_chunks = splitByteArrayIntoPiece(encrypted_file, 163840);

            byte[] decrypted_file = decryptWithAES128(encrypted_file, AES_key, AES_IV);
            string decrypted_file_data_string = Encoding.Default.GetString(decrypted_file);

            Thread.Sleep(300);
            //string chunk_count = encrypted_message_chunks.Count + "::::::::::";
            //byte[] msg = Encoding.Default.GetBytes(chunk_count);
            string chunk_count = encrypted_message_chunks.Count.ToString();

            //socket.Send(msg);
            logs_server.AppendText("\n");
            logs_server.AppendText("file is send in " + encrypted_message_chunks.Count + " pices(s). \n");
            logs_server.AppendText("\n");



            string gathered_messages = owner + "::::::::::" + file_name + "::::::::::" + chunk_count + "::::::::::" + HMAC_file_name_hex + "::::::::::" + HMAC_file_hex + "::::::::::";
            byte[] gathered_messages_byte = Encoding.Default.GetBytes(gathered_messages);
            socket.Send(gathered_messages_byte);

            //byte[] ack_buffer = new byte[64];
            //socket.Receive(ack_buffer);
            //string ack_string = Encoding.Default.GetString(ack_buffer).Trim('\0');
            //logs_remote_server.AppendText(ack_string + "\n");
            //
            //if (ack_string.Contains("start to transfer"))
            //{
            for (int i = 0; i < encrypted_message_chunks.Count; i++)
            {

                byte[] encrypted_msg_chunk = encrypted_message_chunks[i];

                socket.Send(encrypted_msg_chunk);
                logs_server.AppendText("\n");
                logs_server.AppendText(i.ToString() + ": " + Encoding.Default.GetString(encrypted_msg_chunk) + "\n\n"); //generateHexStringFromByteArray(encrypted_msg_chunk)
                logs_server.AppendText("\n");

                logs_server.AppendText("chunk length: " + encrypted_msg_chunk.Length + "\n");
                logs_server.AppendText("\n");
                Thread.Sleep(200);

            }
            //}

            logs_server.AppendText("\n");
            logs_server.AppendText("\n");
            logs_server.AppendText("\n");
            logs_server.AppendText("Full encrypted length byte: " + encrypted_file.Length + "\n");
            byte[] ack = new byte[16];
            socket.Receive(ack);
            string acknowledgment = Encoding.Default.GetString(ack).Trim('\0');
            if (acknowledgment == "1")// acknowledgment == "1"
            {
                logs_server.AppendText("File is successfully recieved by " + reciever + ", HMACs are consistent\n");
                return true;
            }
            else
            {
                logs_server.AppendText("File cannot be replicated by " + reciever + ".\n");
                return false;
            }


        }

        static List<string> getUploadedFileNames()
        {
            string file_path = @"C:\Users\guney\Downloads\revised_432_test\Intro432Proje\Server_project_432\bin\Debug\net5.0-windows\files";
            List<string> uploaded_file_names = new List<string>();
            string[] file_names_array = Directory.GetFiles(file_path);

            foreach (string file in file_names_array)
                uploaded_file_names.Add(Path.GetFileName(file));


            return uploaded_file_names;
        }


        static byte[] applyHMACwithSHA256(byte[] byteInput, byte[] key)
        {
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA256 hmacSHA256 = new HMACSHA256(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA256.ComputeHash(byteInput);

            return result;
        }

        // RSA encryption with varying bit length
        static byte[] encryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                //true flag is set to perform direct RSA encryption using OAEP padding
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // RSA decryption with varying bit length
        static byte[] decryptWithRSA(string input, int algoLength, string xmlStringKey, bool fromHexToByte)
        {
            // convert input string to byte array
            byte[] byteInput;
            if (fromHexToByte)
            {
                byteInput = hexStringToByteArray(input);
            }
            else
            {
                byteInput = Encoding.Default.GetBytes(input);
            }
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);

            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;
            try
            {
                result = rsaObject.Decrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        
        static byte[] encryptWithAES128(byte[] byteInput, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            //byte[] byteInput = hexStringToByteArray(input);
            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;

            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        static byte[] decryptWithAES128(byte[] byteInput, byte[] key, byte[] IV)
        {
            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // set padding mode
            //aesObject.Padding = PaddingMode.Zeros;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }
        
        /*
        static byte[] encryptWithAES128(string input, byte[] key, byte[] IV)
        {
            // Check arguments.
            if (input == null || input.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CFB;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(input);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static byte[] decryptWithAES128(byte[] byteInput, byte[] key, byte[] IV)
        {
            //byte[] byteInput = Encoding.Default.GetBytes(input);
            // Check arguments.
            if (byteInput == null || byteInput.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = "";

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CFB;

                aesAlg.Padding = PaddingMode.Zeros;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(byteInput))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return Encoding.Default.GetBytes(plaintext);
        }
        */
        // signing with RSA
        static byte[] signWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.SignData(byteInput, "SHA256");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        // verifying with RSA
        static bool verifyWithRSA(string input, int algoLength, string xmlString, byte[] signature)
        {
            // convert input string to byte array
            byte[] byteInput = System.Text.Encoding.Default.GetBytes(input);
            
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            bool result = false;

            try
            {
                result = rsaObject.VerifyData(byteInput, "SHA256", signature);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }


        string readFile(string fileName)
        {
            string line;
            using (System.IO.StreamReader fileReader = new System.IO.StreamReader(fileName))
            {
                line = fileReader.ReadLine();
            }

            return line;
        }

        void getKeysFromFile()
        {

            server1_pub_prv = readFile("Server1_pub_prv.txt");
            masterServer_public = readFile("MasterServer_pub.txt");
            server2_public = readFile("Server2_pub.txt");
        }

        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }

        public static byte[] hexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string stringToHexString(string str)
        {
            var sb = new StringBuilder();

            var bytes = Encoding.Unicode.GetBytes(str);
            foreach (var t in bytes)
            {
                sb.Append(t.ToString("X2"));
            }

            return sb.ToString(); // returns: "48656C6C6F20776F726C64" for "Hello world"
        }

        public static string hexToString(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return Encoding.Default.GetString(bytes); // returns: "Hello world" for "48656C6C6F20776F726C64"
        }

        private static List<byte[]> splitByteArrayIntoPiece(byte[] data, int chunk_length)
        {
            List<byte[]> data_chunks = new List<byte[]>();
            int length = data.Length;

            int source_index = 0;
            while (length != 0)
            {
                byte[] chunk;
                if (length >= chunk_length)
                {
                    chunk = new byte[chunk_length];
                    Array.Copy(data, source_index, chunk, 0, chunk_length);
                }
                else
                {
                    int len = data.Length - source_index;
                    chunk = new byte[len];
                    Array.Copy(data, source_index, chunk, 0, len);
                }
                source_index += chunk.Length;
                length -= chunk.Length;
                data_chunks.Add(chunk);
            }

            return data_chunks;
        }

        int seperateMessage(string message)
        {
            int counter = 0;
            int seperator_start_index = 0;
            for (int i = 0; i < message.Length; i++)
            {
                if (message[i] == ':' && message[i + 1] == ':' && message[i + 2] == ':' && message[i + 3] == ':')
                {
                    for (int j = i; j < i + 10; j++)
                    {
                        if (message[j] == ':')
                        {
                            counter++;
                        }
                        else
                        {
                            counter = 0;
                            break;
                        }
                    }
                    if (counter == 10)
                    {
                        seperator_start_index = i;
                        break;
                    }
                }
            }
            return seperator_start_index;
        }

        public static byte[] Combine(List<byte[]> list)
        {
            IEnumerable<byte> result = Enumerable.Empty<byte>();

            foreach (byte[] bytes in list)
            {
                result = result.Concat(bytes);
            }

            byte[] newArray = result.ToArray();
            return newArray;
        }

        public static void saveByteArrayToFileWithFileStream(byte[] data, string fileName)
        {
            string filePath = @"C:\Users\guney\Downloads\revised_432_test\Intro432Proje\Server_project_432\bin\Debug\net5.0-windows\files";
            filePath = filePath + @"\" + fileName;
            //using var stream = File.Create(filePath);
            //stream.Write(data, 0, data.Length);

            using (Stream file = File.OpenWrite(filePath))
            {
                file.Write(data, 0, data.Length);
            }
        }

        string generateKeyForServer_2()
        {
            string key = "";
            byte[] key_byte = new Byte[48];

            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
            random.GetBytes(key_byte);

            server_2SessionKeys.Add(key_byte);

            key = Encoding.Default.GetString(key_byte);

            return key;
        }


        public Form2()
        {
            getKeysFromFile();
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            listening = false;
            terminating = true;
            Environment.Exit(0);
        }

        private void listen_button_Click(object sender, EventArgs e)
        {
            int serverPort;
            Thread acceptThread;
            if (Int32.TryParse(server_port_textBox.Text, out serverPort))
            {
                serverSocket.Bind(new IPEndPoint(IPAddress.Any, serverPort));
                serverSocket.Listen(3);
                listening = true;
                listen_button.Enabled = false;
                acceptThread = new Thread(new ThreadStart(Accept));
                acceptThread.Start();
                logs_server.AppendText("Started listening on port: " + serverPort + "\n");

                //Thread fileReplicationThread = new Thread(new ThreadStart(fileReplication));
                //fileReplicationThread.Start();
            }
            else
            {
                logs_server.AppendText("Please check port number \n");
            }
        }

        private void connect_rmt_btn_Click(object sender, EventArgs e)
        {
            remoteSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            string IP = rmt_ip.Text;
            int port;
            //IP = "127.0.0.1";
            //port = 111;
            if (Int32.TryParse(rmt_port.Text, out port)) //Int32.TryParse(rmt_port.Text, out port)
            {
                try
                {
                    remoteSocket.Connect(IP, port);
                    master_connected = true;
                    logs_server.AppendText("Connected to master server\n");

                    if (master_connected) // always true bu 
                    {
                        //getKeysFromFile();
                        //string message = server_ID.Text + " I_am_a_server";
                        string message = "1" + " I_am_a_server";
                        connectionTypeList.Add("master_server");

                        logs_server.AppendText(message + "\n");
                        Byte[] buffer = Encoding.Default.GetBytes(message);
                        remoteSocket.Send(buffer);
                    }

                    socketList.Add(remoteSocket);
                    Thread receiveMasterThread = new Thread(new ThreadStart(Receive));
                    receiveMasterThread.Start();

                }
                catch
                {
                    logs_server.AppendText("Could not connect to master server\n");
                }
            }
            else
            {
                logs_server.AppendText("Check the port\n");
            }
        }
        private void server2_connect_button_Click(object sender, EventArgs e)
        {
            server_2_socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            string IP = server2_IP_textBox.Text;
            int port;
            //IP = "127.0.0.1";
            //port = 111;
            if (Int32.TryParse(server2_port_textBox.Text, out port)) //Int32.TryParse(rmt_port.Text, out port)
            {
                try
                {
                    server_2_socket.Connect(IP, port);
                    server2_connected = true;
                    logs_server.AppendText("Connected to server-2\n");
                    connectionTypeList.Add("server_2");
                    socketList.Add(server_2_socket);
                    Thread receiveServer2 = new Thread(new ThreadStart(Receive));
                    receiveServer2.Start();

                }
                catch
                {
                    logs_server.AppendText("Could not connect to master server\n");
                }
            }
            else
            {
                logs_server.AppendText("Check the port\n");
            }
        }
        private void Accept()
        {
            while (listening)
            {
                try
                {
                    socketList.Add(serverSocket.Accept());
                    connectionTypeList.Add("client");
                    logs_server.AppendText("A client is connected \n");


                    Thread receiveThread;
                    receiveThread = new Thread(new ThreadStart(Receive));
                    receiveThread.Start();
                }
                catch
                {
                    if (terminating)
                    {
                        listening = false;
                    }
                    else
                    {
                        logs_server.AppendText("The socket stopped working \n");
                    }
                }
            }
        }
        private void Receive()
        {
            Socket s = socketList[socketList.Count - 1];
            bool connected = true;

            while (connected && !terminating)
            {
                try
                {
                    Byte[] buffer = new Byte[2048];
                    s.Receive(buffer);  

                    string incomingMessage = Encoding.Default.GetString(buffer);
                    incomingMessage = incomingMessage.Trim('\0');

                    if (incomingMessage.Contains("This_is_your_session_key_sig:")) // len => 29
                    {
                        //connectionTypeList[socketList.Count - 1] = "master_server";
                        string dummy = incomingMessage.Substring(0, 29);
                        string ecnrtpyed_key_signature = incomingMessage.Substring(29);

                        byte[] xxx = Encoding.Default.GetBytes(incomingMessage);


                        int counter = 0;
                        int sperator_start_index = 0;
                        for (int i = 0; i < ecnrtpyed_key_signature.Length; i++)
                        {
                            if (ecnrtpyed_key_signature[i] == ':' && ecnrtpyed_key_signature[i + 1] == ':' && ecnrtpyed_key_signature[i + 2] == ':' && ecnrtpyed_key_signature[i + 3] == ':')
                            {
                                for (int j = i; j < i + 10; j++)
                                {
                                    if (ecnrtpyed_key_signature[j] == ':')
                                    {
                                        counter++;
                                    }
                                    else
                                    {
                                        counter = 0;
                                        break;
                                    }
                                }
                                if (counter == 10)
                                {
                                    sperator_start_index = i;
                                    break;
                                }
                            }
                        }
                        //logs_server.AppendText("SEPERATOR INDEX " + sperator_start_index + "\n");
                        //logs_server.AppendText(counter + "tane iki nokta ust uste var.\n");

                        string encrypted_key = ecnrtpyed_key_signature.Substring(0, sperator_start_index);
                        string server_signature_string = ecnrtpyed_key_signature.Substring(sperator_start_index + 10);// , ecnrtpyed_key_signature.Length - encrypted_key.Length - 10

                        byte[] encrypted_key_byte = hexStringToByteArray(encrypted_key);
                        byte[] server_signature_byte = hexStringToByteArray(server_signature_string);


                        logs_server.AppendText("SIGNATURE: " + server_signature_string + "\n");
                        logs_server.AppendText("ENC_KEY: " + encrypted_key + "\n");
                        logs_server.AppendText("ENC_KEY_LEN: " + encrypted_key_byte.Length + "\n");


                        if (verifyWithRSA(encrypted_key, 3072, masterServer_public, server_signature_byte))
                        {
                            logs_server.AppendText("Signature for session key is verified.\n");
                            byte[] session_key = decryptWithRSA(encrypted_key, 3072, server1_pub_prv, true); // input is in hex format, so we put true
                            string hex_session_key = generateHexStringFromByteArray(session_key);
                            logs_server.AppendText("KEY: " + hex_session_key + "\n");

                            Array.Copy(session_key, 0, AES_128_key_master, 0, 16);
                            Array.Copy(session_key, 16, AES_128_IV_master, 0, 16);
                            Array.Copy(session_key, 32, AES_128_HMAC_master, 0, 16);

                            logs_server.AppendText("AES_KEY: " + Encoding.Default.GetString(AES_128_key_master) + "\n");
                            logs_server.AppendText("AES_IV: " + Encoding.Default.GetString(AES_128_IV_master) + "\n");
                            logs_server.AppendText("AES_HMAC: " + Encoding.Default.GetString(AES_128_HMAC_master) + "\n");


                        }
                        else
                        {
                            logs_server.AppendText("Signature for session key is not verified.\n");
                        }
                    }

                    else if (incomingMessage.Contains("I will send a file"))
                    {
                        try
                        {
                            // first server recieves keys and file name, then it recieves file in chunks

                            Byte[] buffer_2 = new Byte[4096];
                            s.Receive(buffer_2);

                            string name_and_keys = Encoding.Default.GetString(buffer_2);
                            name_and_keys = name_and_keys.Trim('\0');
                            int first_seperator_index = seperateMessage(name_and_keys);
                            string file_name = name_and_keys.Substring(0, first_seperator_index);
                            string key_and_IV_and_dummy = name_and_keys.Substring(first_seperator_index + 10);
                            int second_seperator_index = seperateMessage(key_and_IV_and_dummy);
                            string encrypted_AES_key = key_and_IV_and_dummy.Substring(0, second_seperator_index);
                            string encrypted_AES_IV_and_dummy = key_and_IV_and_dummy.Substring(second_seperator_index + 10);
                            int third_seperator_index = seperateMessage(encrypted_AES_IV_and_dummy);
                            string encrypted_AES_IV = encrypted_AES_IV_and_dummy.Substring(0, third_seperator_index);


                            logs_server.AppendText("ENC_KEY_HEX_LEN: " + encrypted_AES_key.Length + "\n");
                            logs_server.AppendText("ENC_IV_HEX_LEN: " + encrypted_AES_IV.Length + "\n");

                            byte[] AES_key = decryptWithRSA(encrypted_AES_key, 3072, server1_pub_prv, true);
                            byte[] AES_IV = decryptWithRSA(encrypted_AES_IV, 3072, server1_pub_prv, true);

                            // bunlar hex cunku client encryptledigi keyler hex formatinda
                            string AES_key_hex = Encoding.Default.GetString(AES_key);
                            string AES_IV_hex = Encoding.Default.GetString(AES_IV);

                            string AES_key_string = hexToString(AES_key_hex);
                            string AES_IV_string = hexToString(AES_IV_hex);

                            byte[] AES_key_byte = hexStringToByteArray(AES_key_hex);
                            byte[] AES_IV_byte = hexStringToByteArray(AES_IV_hex);



                            logs_server.AppendText("AES_key_string: " + AES_key_string + "\n");
                            logs_server.AppendText("AES_IV_string: " + AES_IV_string + "\n");

                            logs_server.AppendText("AES_key_HEX: " + AES_key_hex + "\n");
                            logs_server.AppendText("AES_IV_HEX: " + AES_IV_hex + "\n");

                            logs_server.AppendText("KEY_LENGTH:" + AES_key_byte.Length + "\n");
                            logs_server.AppendText("IV_LENGTH:" + AES_IV_byte.Length + "\n");

                            // creatinf dummy file
                            //byte[] dummy = null;
                            //saveByteArrayToFileWithFileStream(dummy, file_name);
                            string filePath = @"C:\Users\guney\Downloads\revised_432_test\Intro432Proje\Server_project_432\bin\Debug\net5.0-windows\files";
                            filePath = filePath + @"\" + file_name;
                            System.IO.File.WriteAllLines(filePath, new string[0]);

                            // get how many parts the file will be divided into
                            Byte[] buffer_chunk_count = new Byte[128];
                            s.Receive(buffer_chunk_count);
                            string chunks_count_string = Encoding.Default.GetString(buffer_chunk_count).Trim('\0');

                            int seperator_index = seperateMessage(chunks_count_string);
                            string chunks_count_string_splitted = chunks_count_string.Substring(0, seperator_index);

                            int chunks_count;
                            Int32.TryParse(chunks_count_string_splitted, out chunks_count);
                            logs_server.AppendText("\n");
                            logs_server.AppendText("file is recieved in " + chunks_count_string_splitted + " pices(s). \n");
                            logs_server.AppendText("\n");

                            string dummy_string = "start to transfer";
                            byte[] dummy_byte = Encoding.Default.GetBytes(dummy_string);
                            s.Send(dummy_byte);
                            logs_server.AppendText(Encoding.Default.GetString(dummy_byte) + "\n");

                            List<string> file_chunks = new List<string>();

                            // recieving files in 2048 byte chunks:
                            List<byte[]> recieved_chunks_list = new List<byte[]>();
                            for (int i = 0; i < chunks_count; i++)
                            {

                                Byte[] buffer_file_chunk = new Byte[163840];
                                s.Receive(buffer_file_chunk);
                                string file_chunk_string = Encoding.Default.GetString(buffer_file_chunk).Trim('\0');

                                // removing dummy bytes from buffer_file_chunk
                                int j = buffer_file_chunk.Length - 1;
                                while (buffer_file_chunk[j] == 0)
                                    --j;
                                // now foo[i] is the last non-zero byte
                                byte[] trimmed_file_chunk = new byte[j + 1];
                                Array.Copy(buffer_file_chunk, trimmed_file_chunk, j + 1);

                                recieved_chunks_list.Add(trimmed_file_chunk);

                                logs_server.AppendText("\n");
                                logs_server.AppendText(i.ToString() + ": " + file_chunk_string + "\n\n"); // generateHexStringFromByteArray(trimmed_file_chunk)
                                logs_server.AppendText("\n");

                                logs_server.AppendText("chunk length: " + trimmed_file_chunk.Length + "\n");

                                logs_server.AppendText("\n");

                                buffer_file_chunk = null;
                            }


                            byte[] encrypted_file = Combine(recieved_chunks_list);

                            logs_server.AppendText("\n");
                            logs_server.AppendText("\n");
                            logs_server.AppendText("\n");
                            logs_server.AppendText("Full encrypted message: " + Encoding.Default.GetString(encrypted_file) + "\n");
                            logs_server.AppendText("Full encrypted length byte: " + encrypted_file.Length + "\n");

                            byte[] decrypted_file = decryptWithAES128(encrypted_file, AES_key_byte, AES_IV_byte);
                            //logs_server.AppendText("FILE: " + Encoding.Default.GetString(decrypted_file) + "\n");
                            saveByteArrayToFileWithFileStream(decrypted_file, file_name);

                            string file_string = generateHexStringFromByteArray(decrypted_file);
                            byte[] file_signature = signWithRSA(file_string, 3072, server1_pub_prv);  //file_string                 
                            s.Send(file_signature);
                            logs_server.AppendText("signature length " + file_signature.Length + "\n");


                            byte[] ack_message = new byte[4];
                            s.Receive(ack_message);
                            string m = Encoding.Default.GetString(ack_message).Trim('\0');
                            if (m == "1")
                            {
                                logs_server.AppendText("signature is verified by the client, file is saved \n");
                                not_replicated_files.Add(decrypted_file);
                                not_replicated_file_names.Add(file_name);
                                saveByteArrayToFileWithFileStream(decrypted_file, file_name);
                            }
                            else
                            {
                                logs_server.AppendText("signature is not verified by the client, file is saved \n");
                            }
                        }
                        catch
                        {
                            logs_server.AppendText("something went wrong. \n");
                        }
                    }
                    else if (incomingMessage.Contains("I_am_a_server"))
                    {
                        connectionTypeList[socketList.Count - 1] = "server_2";
                        //server_2_socket = socketList[socketList.Count - 1];
                        server2_connected = true;
                        server_2_socket = s;

                        string server_id = incomingMessage.Substring(0, 1); // getting first word of the message which is server id.
                        logs_server.AppendText("Server-" + server_id + "is connected\n");

                        string key = generateKeyForServer_2();
                        byte[] byte_key = Encoding.Default.GetBytes(key);
                        string hex_key = generateHexStringFromByteArray(byte_key);


                        AES_128_key_server_2 = new byte[16];
                        AES_128_IV_server_2 = new byte[16];
                        AES_128_HMAC_server_2 = new byte[16];

                        Array.Copy(byte_key, 0, AES_128_key_server_2, 0, 16);
                        Array.Copy(byte_key, 16, AES_128_IV_server_2, 0, 16);
                        Array.Copy(byte_key, 32, AES_128_HMAC_server_2, 0, 16);

                        logs_server.AppendText("AES_KEY: " + Encoding.Default.GetString(AES_128_key_server_2) + "\n");
                        logs_server.AppendText("AES_IV: " + Encoding.Default.GetString(AES_128_IV_server_2) + "\n");
                        logs_server.AppendText("AES_HMAC: " + Encoding.Default.GetString(AES_128_HMAC_server_2) + "\n");

                        byte[] encrypted_key;

                        encrypted_key = encryptWithRSA(key, 3072, server2_public);

                        string encrypted_key_string = Encoding.Default.GetString(encrypted_key);
                        string hex_encrypted_key = generateHexStringFromByteArray(encrypted_key);


                        byte[] signature = signWithRSA(hex_encrypted_key, 3072, server1_pub_prv);
                        string signature_string = Encoding.Default.GetString(signature);
                        string hex_signature_string = generateHexStringFromByteArray(signature);

                        string encrypted_key_signature_string = hex_encrypted_key + "::::::::::" + hex_signature_string; // 10 tane :
                        string m = "This_is_your_session_key_sig_s2:" + encrypted_key_signature_string;
                        byte[] encrypted_key_signature_message = Encoding.Default.GetBytes(m);


                        logs_server.AppendText("SIGNATURE: " + hex_signature_string + "\n");
                        logs_server.AppendText("ENC_KEY: " + hex_encrypted_key + "\n");
                        logs_server.AppendText("KEY: " + hex_key + "\n");


                        s.Send(encrypted_key_signature_message);
                    }
                    else if (incomingMessage.Contains("File_Replication"))
                    {
                        byte[] AES_key = new byte[16];
                        byte[] AES_IV = new byte[16];
                        byte[] HMAC = new byte[16];


                        byte[] message_buffer = new byte[4096];
                        s.Receive(message_buffer);
                        string message = Encoding.Default.GetString(message_buffer).Trim('\0');

                        int seperator_index = seperateMessage(message);
                        string sender = message.Substring(0, seperator_index);
                        message = message.Substring(seperator_index + 10);

                        seperator_index = seperateMessage(message);
                        string file_name = message.Substring(0, seperator_index);
                        message = message.Substring(seperator_index + 10);                
                        
                        seperator_index = seperateMessage(message);
                        string chunks_count_string = message.Substring(0, seperator_index);
                        message = message.Substring(seperator_index + 10);

                        seperator_index = seperateMessage(message);
                        string recieved_HMAC_file_name_hex = message.Substring(0, seperator_index);
                        message = message.Substring(seperator_index + 10);

                        seperator_index = seperateMessage(message);
                        string recieved_HMAC_file_hex = message.Substring(0, seperator_index);
                        //message = message.Substring(seperator_index + 10);


                        //byte[] sender_buffer = new byte[128];
                        //s.Receive(sender_buffer);
                        //string sender = Encoding.Default.GetString(sender_buffer).Trim('\0');
                        if (sender == "master_server")
                        {
                            AES_key = AES_128_key_master;
                            AES_IV = AES_128_IV_master;
                            HMAC = AES_128_HMAC_master;
                        }
                        else
                        {
                            AES_key = AES_128_key_server_2;
                            AES_IV = AES_128_IV_server_2;
                            HMAC = AES_128_HMAC_server_2;
                        }

                        //byte[] hmac_messages = new byte[2048];
                        //s.Receive(hmac_messages);
                        //string hmac_messages_hex = Encoding.Default.GetString(hmac_messages).Trim('\0');
                        //int seperator_index = seperateMessage(hmac_messages_hex);
                        //string recieved_HMAC_file_name_hex = hmac_messages_hex.Substring(0, seperator_index);
                        //string recieved_HMAC_file_hex = hmac_messages_hex.Substring(seperator_index + 10);

                        //byte[] enc_file_name = new byte[2048];
                        //s.Receive(enc_file_name);
                        // 222222
                        //string enc_file_name_string = Encoding.Default.GetString(enc_file_name).Trim('\0');
                        //byte[] enc_file_name_byte = Encoding.Default.GetBytes(enc_file_name_string);
                        //byte[] file_name_byte = decryptWithAES128(enc_file_name, AES_key, AES_IV);
                        //string file_name = Encoding.Default.GetString(file_name_byte);
                        // 22222
                        //string file_name = Encoding.Default.GetString(enc_file_name).Trim('\0');
                        logs_server.AppendText("Recieved file name: " + file_name + "\n");

                        // get how many parts the file will be divided into
                        //Byte[] buffer_chunk_count = new Byte[128];
                        //s.Receive(buffer_chunk_count);
                        //string chunks_count_string = Encoding.Default.GetString(buffer_chunk_count).Trim('\0');

                        //seperator_index = seperateMessage(chunks_count_string);
                        //string chunks_count_string_splitted = chunks_count_string.Substring(0, seperator_index);

                        int chunks_count;
                        Int32.TryParse(chunks_count_string, out chunks_count);

                        logs_server.AppendText("\n");
                        logs_server.AppendText("file is recieved in " + chunks_count_string + " pices(s). \n");
                        logs_server.AppendText("\n");

                        //string dummy_string = "start to transfer";
                        //byte[] dummy_byte = Encoding.Default.GetBytes(dummy_string);
                        //s.Send(dummy_byte);
                        //logs_server.AppendText(Encoding.Default.GetString(dummy_byte) + "\n");

                        List<string> file_chunks = new List<string>();

                        // recieving files in 163840 byte chunks:
                        List<byte[]> recieved_chunks_list = new List<byte[]>();
                        for (int i = 0; i < chunks_count; i++)
                        {

                            Byte[] buffer_file_chunk = new Byte[163840];
                            s.Receive(buffer_file_chunk);
                            string file_chunk_string = Encoding.Default.GetString(buffer_file_chunk).Trim('\0');

                            // removing dummy bytes from buffer_file_chunk
                            int j = buffer_file_chunk.Length - 1;
                            while (buffer_file_chunk[j] == 0)
                                --j;
                            // now foo[i] is the last non-zero byte
                            byte[] trimmed_file_chunk = new byte[j + 1];
                            Array.Copy(buffer_file_chunk, trimmed_file_chunk, j + 1);

                            recieved_chunks_list.Add(trimmed_file_chunk);

                            logs_server.AppendText("\n");
                            logs_server.AppendText(i.ToString() + ": " + file_chunk_string + "\n\n"); // generateHexStringFromByteArray(trimmed_file_chunk)
                            logs_server.AppendText("\n");

                            logs_server.AppendText("chunk length: " + trimmed_file_chunk.Length + "\n");

                            logs_server.AppendText("\n");

                            buffer_file_chunk = null;
                        }

                        byte[] encrypted_file = Combine(recieved_chunks_list);

                        logs_server.AppendText("\n");
                        logs_server.AppendText("\n");
                        logs_server.AppendText("\n");
                        logs_server.AppendText("Full encrypted message: " + Encoding.Default.GetString(encrypted_file) + "\n");
                        logs_server.AppendText("Full encrypted length byte: " + encrypted_file.Length + "\n");

                        byte[] decrypted_file = decryptWithAES128(encrypted_file, AES_key, AES_IV);

                        byte[] HMAC_file = applyHMACwithSHA256(decrypted_file, HMAC);
                        string HMAC_file_hex = generateHexStringFromByteArray(HMAC_file);

                        //byte[] HMAC_file_name = applyHMACwithSHA256(file_name_byte, HMAC);
                        //string HMAC_file_name_hex = generateHexStringFromByteArray(HMAC_file_name);
                        //Thread.Sleep(300);
                        //if (HMAC_file_hex == recieved_HMAC_file_hex /*&& HMAC_file_name_hex == recieved_HMAC_file_name_hex*/)
                        //{
                        //    saveByteArrayToFileWithFileStream(decrypted_file, file_name);
                        //    string ack = "1";
                        //    byte[] ack_byte = Encoding.Default.GetBytes(ack);
                        //    s.Send(ack_byte);
                        //}
                        //else
                        //{
                        //    string ack = "0";
                        //    byte[] ack_byte = Encoding.Default.GetBytes(ack);
                        //    s.Send(ack_byte);
                        //}

                        if (HMAC_file_hex == recieved_HMAC_file_hex)
                        {
                            logs_server.AppendText("Replicated file is verified, and successfully saved. \n");
                            saveByteArrayToFileWithFileStream(decrypted_file, file_name);
                            string ack = "1";
                            byte[] ack_byte = Encoding.Default.GetBytes(ack);
                            s.Send(ack_byte);
                        }
                        else
                        {
                            logs_server.AppendText("Replicated file is not verified. \n");
                            string ack = "0";
                            byte[] ack_byte = Encoding.Default.GetBytes(ack);
                            s.Send(ack_byte);
                        }


                    }
                    else if (incomingMessage.Contains("server2_master_server_connected"))
                    {
                        //logs_server.AppendText("Server-2 and Master-Server connected.");
                        server2_master_connected = true;
                    }
                    else if (incomingMessage.Contains("server2_master_server_disconnected"))
                    {
                        //logs_server.AppendText("Server-2 and Master-Server disconnected.");
                        server2_master_connected = false;
                    }
                    else if (incomingMessage.Contains("Request_Download"))
                    {
                        int seperator_index = seperateMessage(incomingMessage);
                        string requested_file_name = incomingMessage.Substring(seperator_index + 10);
                        List<string> uploaded_file_names = getUploadedFileNames();
                        // if server has requested file
                        if (uploaded_file_names.Contains(requested_file_name))
                        {

                            string file_path = @"C:\Users\guney\Downloads\revised_432_test\Intro432Proje\Server_project_432\bin\Debug\net5.0-windows\files";
                            file_path = file_path + @"\" + requested_file_name;

                            byte[] file_data = File.ReadAllBytes(file_path); // byte[]

                            List<byte[]> file_chunks = splitByteArrayIntoPiece(file_data, 163840); //8912 //20480


                            byte[] ack_msg = Encoding.Default.GetBytes("1::::::::::" + file_chunks.Count.ToString()); // saying client that file is exist.
                            s.Send(ack_msg);

                            for (int i = 0; i < file_chunks.Count; i++)
                            {

                                byte[] encrypted_msg_chunk = file_chunks[i];

                                s.Send(encrypted_msg_chunk);
                                logs_server.AppendText("\n");
                                logs_server.AppendText(i.ToString() + ": " + Encoding.Default.GetString(encrypted_msg_chunk) + "\n\n"); //generateHexStringFromByteArray(encrypted_msg_chunk)
                                logs_server.AppendText("\n");
                                logs_server.AppendText("chunk length: " + encrypted_msg_chunk.Length + "\n");
                                logs_server.AppendText("\n");
                                Thread.Sleep(100);

                            }
                            Thread.Sleep(100);
                            string file_data_hex = generateHexStringFromByteArray(file_data);
                            byte[] file_signature = signWithRSA(file_data_hex, 3072, server1_pub_prv);
                            s.Send(file_signature);
                        }
                        else
                        {
                            byte[] ack_msg = Encoding.Default.GetBytes("0"); // saying client that file is not exist.
                            s.Send(ack_msg);
                        }

                    }
                    if (master_connected && server2_connected && server2_master_connected)
                    {
                        try
                        {
                            int master_server_index = connectionTypeList.IndexOf("master_server");
                            int server_2_index = connectionTypeList.IndexOf("server_2");
                            remoteSocket = socketList[master_server_index];
                            //server_2_socket = socketList[server_2_index];

                            while (not_replicated_files.Count > 0 && not_replicated_file_names.Count > 0)
                            {
                                byte[] file_data = not_replicated_files[0];
                                string file_name = not_replicated_file_names[0];

                                bool isReplicated_master_server = distributeFile(remoteSocket, file_data, file_name, "server_1", "master_server");
                                bool isReplicated_server2 = distributeFile(server_2_socket, file_data, file_name, "server_1", "server_2");

                                if (isReplicated_master_server && isReplicated_server2)
                                {
                                    not_replicated_files.RemoveAt(0);
                                    not_replicated_file_names.RemoveAt(0);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            logs_server.AppendText(e.ToString() + "\n");
                        }
                    }
                }
                catch (Exception e)
                {
                    //logs_server.AppendText(e.Message + "\n");

                    if (connectionTypeList[socketList.Count - 1] == "master_server")
                    {
                        logs_server.AppendText("Master-Server is disconnected. \n");
                        master_connected = false;
                        connectionTypeList.Remove("master_server");


                    }

                    else if (connectionTypeList[socketList.Count - 1] == "server_2")
                    {
                        logs_server.AppendText("Server-2 is disconnected. \n");
                        server2_connected = false;
                        connectionTypeList.Remove("server_2");
                    }
                    else
                    {
                        logs_server.AppendText("A client is disconnected. \n");
                    }

                    s.Close();
                    socketList.Remove(s);
                    connected = false;
                }

            }

        }

        private void logs_server_TextChanged(object sender, EventArgs e)
        {

        }
        /*
private void fileReplication()
{
   while (listening)
   {
       if (master_connected && server2_connected && server2_master_connected)
       {
           try
           {
               int master_server_index = connectionTypeList.IndexOf("master_server");
               int server_2_index = connectionTypeList.IndexOf("server_2");
               //remoteSocket = socketList[master_server_index];
               //server_2_socket = socketList[server_2_index];

               while (not_replicated_files.Count > 0 && not_replicated_file_names.Count > 0)
               {
                   byte[] file_data = not_replicated_files[0];
                   string file_name = not_replicated_file_names[0];

                   bool isReplicated_master_server = distributeFile(remoteSocket, file_data, file_name, "server_1", "master_server");
                   bool isReplicated_server2 = distributeFile(server_2_socket, file_data, file_name, "server_1", "server_2");

                   if (isReplicated_master_server && isReplicated_server2)
                   {
                       not_replicated_files.RemoveAt(0);
                       not_replicated_file_names.RemoveAt(0);
                   }

                   //if (isReplicated_server1)
                   //{
                   //    not_replicated_files.RemoveAt(0);
                   //    not_replicated_file_names.RemoveAt(0);
                   //}
               }
           }
           catch (Exception e)
           {
               logs_server.AppendText(e.ToString() + "\n");
           }
       }
   }
}
*/
    }

}


//List<byte[]> encrypted_message_chunks = splitByteArrayIntoPiece(server_signature_byte, 384);
//List<byte[]> decrypted_messages = new List<byte[]>();

//for (int i = 0; i < encrypted_message_chunks.Count; i++)
//{
//    byte[] encrypted_msg = encrypted_message_chunks[i];
//    string encrypted_msg_string = Encoding.Default.GetString(encrypted_msg).Trim('\0');
//    byte[] decrypted_key = decryptWithRSA(encrypted_msg_string, 3072, server1_pub_prv);
//    decrypted_messages.Add(decrypted_key);
//    logs_server.AppendText(i + ". " + Encoding.Default.GetString(decrypted_key) + "\n");
//}


/*
// Accept a TcpClient    

TcpListener tcpListener = new TcpListener(IPAddress.Any, 11);
tcpListener.Start();

TcpClient tcpClient = tcpListener.AcceptTcpClient();

logs_server.AppendText("Connected to client\n");

StreamReader reader = new StreamReader(tcpClient.GetStream());

// The first message from the client is the file size    
string cmdFileSize = reader.ReadLine();

// The first message from the client is the filename    
string cmdFileName = reader.ReadLine();

int length = Convert.ToInt32(cmdFileSize);
byte[] buffer_recieve = new byte[length];
int received = 0;
int read = 0;
int size = 1024;
int remaining = 0;

// Read bytes from the client using the length sent from the client    
while (received < length)
{
    remaining = length - received;
    if (remaining < size)
    {
        size = remaining;
    }
    read = tcpClient.GetStream().Read(buffer_recieve, received, size);
    received += read;
}

// Save the file using the filename sent by the client    
using (FileStream fStream = new FileStream(Path.GetFileName(cmdFileName), FileMode.Create))
{
    fStream.Write(buffer_recieve, 0, buffer_recieve.Length);
    fStream.Flush();
    fStream.Close();
}
logs_server.AppendText("File received and saved in " + Environment.CurrentDirectory + "\n");
*/

// key:"3419EBABABA641E5665E0C675FD559F4153A3B3236D385F91CBFA6050129D03A24AE6DEB95762D6B732DC759760AF878CDE70C5753558760CC7D9C3FCA608AD3952CE207615F48B01CDEEEF873BA01D877BB22F937ED90331B94C6AB7BDC232382270441C72D8340F73634304A2A611108A643649ED8C869EB7B1AB4C070F279FAC3F775C29CE10647DDD439B9679E603C922A571E75A76FCBA65E75792DA9E0AE2D5D4FECCE6FE0C6B38BB163BB2B13FFEE2F6FAB006AE56BFE1000F5852BEC632314500C29191343554D136F55785F8CA1C107CD7E87C8BC2ED2F4ABEE8447BE74D196EBC0EE63EAC8521D595984D02BE66FE61426AB7F987F11960E2F563EA6E13CF3133B31396DD24CFF4A78101D50B674A8E7B4BF8BABF22A2384985FDD0F5FFA803169111C6796D3E0951B52D4A290A564A5A1ACB4FB52F114E6EDDDDEBA066C8C4AA4E7AD71DA5E1B0079B7C780390C367DB4EBBBB43B1E819815A22A393DB71F3962F48CF9342ED0B89EBDA05F6A00636DD07C9466971CF94DEB85CD"
// iv: "207753FB80EED48BC3ECD88FFD7622CA70FD92C0E8B6845DA8CE4D520565813E6CFCFEC12A30089D81FF44B6D50351F0A3E17353CB03CCD02A7867DF8039D55104AA0BAF33BC906A0C494EB527DA7A80BC5434CACDBFEB72DCC27091E80841FBE8170F0336DF07FC9DD023F7171ED36BE425A57D3D1283CE335ACA940BEC51F3D9384CA5A193CADAC6625FBA47B4E446569506ACC85F51EEF3DD055E9DC99F3D46B22069C01A0C5DF6F81E8C35460AA0445669BF2D7C152FB2F461295B893F07D2B7898C6A571C3EC17635C0F08FF142B8AAF38C748D0F36BB85EF7577EE0AE928807A3540BD957C740F09B8A5CE25AE79DAE3C6012BCF97E7B0350E256ADC6789AB2A201F2BB204954588D7A05AC25CD9556B2485AF4F6C802D6A9C79D131479D157EA04E4915FE73F74B15E0C0B75E61D56665861043247438D4495EEBB0A5D1A29E9C52C81BB9EAD9065AC4849C1188211D439101620BF1EFC14A4FCAE32C500E14DF883F6B9AD98340C1CC3CC8E49A1C61074C399A9FC0A34040153A29241::::::::::"

// "3419EBABABA641E5665E0C675FD559F4153A3B3236D385F91CBFA6050129D03A24AE6DEB95762D6B732DC759760AF878CDE70C5753558760CC7D9C3FCA608AD3952CE207615F48B01CDEEEF873BA01D877BB22F937ED90331B94C6AB7BDC232382270441C72D8340F73634304A2A611108A643649ED8C869EB7B1AB4C070F279FAC3F775C29CE10647DDD439B9679E603C922A571E75A76FCBA65E75792DA9E0AE2D5D4FECCE6FE0C6B38BB163BB2B13FFEE2F6FAB006AE56BFE1000F5852BEC632314500C29191343554D136F55785F8CA1C107CD7E87C8BC2ED2F4ABEE8447BE74D196EBC0EE63EAC8521D595984D02BE66FE61426AB7F987F11960E2F563EA6E13CF3133B31396DD24CFF4A78101D50B674A8E7B4BF8BABF22A2384985FDD0F5FFA803169111C6796D3E0951B52D4A290A564A5A1ACB4FB52F114E6EDDDDEBA066C8C4AA4E7AD71DA5E1B0079B7C780390C367DB4EBBBB43B1E819815A22A393DB71F3962F48CF9342ED0B89EBDA05F6A00636DD07C9466971CF94DEB85CD::::::::::207753FB80EED48BC3ECD88FFD7622CA70FD92C0E8B6845DA8CE4D520565813E6CFCFEC12A30089D81FF44B6D50351F0A3E17353CB03CCD02A7867DF8039D55104AA0BAF33BC906A0C494EB527DA7A80BC5434CACDBFEB72DCC27091E80841FBE8170F0336DF07FC9DD023F7171ED36BE425A57D3D1283CE335ACA940BEC51F3D9384CA5A193CADAC6625FBA47B4E446569506ACC85F51EEF3DD055E9DC99F3D46B22069C01A0C5DF6F81E8C35460AA0445669BF2D7C152FB2F461295B893F07D2B7898C6A571C3EC17635C0F08FF142B8AAF38C748D0F36BB85EF7577EE0AE928807A3540BD957C740F09B8A5CE25AE79DAE3C6012BCF97E7B0350E256ADC6789AB2A201F2BB204954588D7A05AC25CD9556B2485AF4F6C802D6A9C79D131479D157EA04E4915FE73F74B15E0C0B75E61D56665861043247438D4495EEBB0A5D1A29E9C52C81BB9EAD9065AC4849C1188211D439101620BF1EFC14A4FCAE32C500E14DF883F6B9AD98340C1CC3CC8E49A1C61074C399A9FC0A34040153A29241::::::::::"