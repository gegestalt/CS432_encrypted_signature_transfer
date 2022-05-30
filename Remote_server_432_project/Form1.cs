using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.IO;
using System.Linq;

namespace Remote_server_432_project
{
    public partial class Form1 : Form
    {
        bool terminating = false;
        bool listening = false;
        Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        Socket server_1_socket;// = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        Socket server_2_socket;// = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        List<Socket> socketList = new List<Socket>(); // list of client socket connected to server
        List<Byte[]> serverSessionKeys = new List<Byte[]>(); // list of session keys that distributed to servers.
        List<string> serverIDs = new List<string>(); // list of server IDs.
        List<string> connectionTypeList = new List<string>(); // store the type of the connected socket (client/server1/server2);
        List<byte[]> not_replicated_files = new List<byte[]>(); // store recieved files when all servers are not connected
        List<string> not_replicated_file_names = new List<string>(); // store recieved file names when all servers are not connected


        bool server_1_connected = false;
        bool server_2_connected = false;
        bool server_1_server_2_connected = false; // SERVER 1 SERVER 2 BAGLANTISINI MESAJ OLARAK ALDIGIMIZDA BUNU FALSE OLARAK DEGISTIRMEK LAZIM

        bool server_1_connection_ack = false; // server1 baglandiginda bu deger true olucak, ne zaman server2 baglanirsa ve bu deger trueyse, server1 in bagli oldugu mesaji server2 ye iletilecek.
        bool server_2_connection_ack = false;

        string masterServer_pub_prv;
        string server1_public;
        string server2_public;

        byte[] AES_128_key_server_2 = new byte[16];
        byte[] AES_128_IV_server_2 = new byte[16];
        byte[] AES_128_HMAC_server_2 = new byte[16];

        byte[] AES_128_key_server_1 = new byte[16];
        byte[] AES_128_IV_server_1 = new byte[16];
        byte[] AES_128_HMAC_server_1 = new byte[16];


        bool distributeFile(Socket socket, byte[] file_data, string file_name, string owner, string reciever)
        {
            byte[] AES_key = new byte[16];
            byte[] AES_IV = new byte[16];
            byte[] HMAC = new byte[16];

            if (reciever == "server_1")
            {
                AES_key = AES_128_key_server_1;
                AES_IV = AES_128_IV_server_1;
                HMAC = AES_128_HMAC_server_1;
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
            logs_remote_server.AppendText("\n");
            logs_remote_server.AppendText("file is send in " + encrypted_message_chunks.Count + " pices(s). \n");
            logs_remote_server.AppendText("\n");

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
                    logs_remote_server.AppendText("\n");
                    logs_remote_server.AppendText(i.ToString() + ": " + Encoding.Default.GetString(encrypted_msg_chunk) + "\n\n"); //generateHexStringFromByteArray(encrypted_msg_chunk)
                    logs_remote_server.AppendText("\n");

                    logs_remote_server.AppendText("chunk length: " + encrypted_msg_chunk.Length + "\n");
                    logs_remote_server.AppendText("\n");
                    Thread.Sleep(200);

                }
            //}

            logs_remote_server.AppendText("\n");
            logs_remote_server.AppendText("\n");
            logs_remote_server.AppendText("\n");
            logs_remote_server.AppendText("Full encrypted length byte: " + encrypted_file.Length + "\n");
            byte[] ack = new byte[16];
            socket.Receive(ack);
            string acknowledgment = Encoding.Default.GetString(ack).Trim('\0');
            if (acknowledgment == "1")// acknowledgment == "1"
            {
                logs_remote_server.AppendText("File is successfully recieved by " + reciever +", HMACs are consistent\n");
                return true;
            }
            else
            {
                logs_remote_server.AppendText("File cannot be replicated by " + reciever + ".\n");
                return false;
            }
        }

        static List<string> getUploadedFileNames()
        {
            string file_path = @"C:\Users\guney\Downloads\revised_432_test\Intro432Proje\Remote_server_432_project\bin\Debug\net5.0-windows\files";
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
            byte[] byteInput = Encoding.Default.GetBytes(input);
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
            masterServer_pub_prv = readFile("MasterServer_pub_prv.txt");
            server1_public = readFile("Server1_pub.txt");
            server2_public = readFile("Server2_pub.txt");
        }



        string generateKeyForServer()
        {
            string key = "";
            byte[] key_byte = new Byte[48];

            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
            random.GetBytes(key_byte);

            serverSessionKeys.Add(key_byte);

            key = Encoding.Default.GetString(key_byte);

            return key;
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
            string filePath = @"C:\Users\guney\Downloads\revised_432_test\Intro432Proje\Remote_server_432_project\bin\Debug\net5.0-windows\files";
            filePath = filePath + @"\" + fileName;
            //using var stream = File.Create(filePath);
            //stream.Write(data, 0, data.Length);

            using (Stream file = File.OpenWrite(filePath))
            {
                file.Write(data, 0, data.Length);
            }
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
        public Form1()
        {
            getKeysFromFile();
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            listening = false;
            terminating = true;
            Environment.Exit(0);
        }
        private void button1_Click(object sender, EventArgs e)
        {
            //getKeysFromFile();
            //logs_remote_server.AppendText(masterServer_pub_prv + "\n");

            string portnum = port_textBox.Text;
            int port_num;

            if (Int32.TryParse(portnum, out port_num))
            {
                serverSocket.Bind(new IPEndPoint(IPAddress.Any, port_num));
                serverSocket.Listen(3);

                listening = true;
                listen_button.Enabled = false;
                Thread acceptThread = new Thread(new ThreadStart(Accept));
                acceptThread.Start();

                //Thread fileReplicationThread = new Thread(new ThreadStart(fileReplication));
                //fileReplicationThread.Start();

                logs_remote_server.AppendText("Started listening. \n");
            }
            else
            {
                logs_remote_server.AppendText("Check the port number. \n");
            }
        }
        private void Accept()
        {
            while (listening)
            {
                try
                {
                    Socket newClient = serverSocket.Accept();
                    socketList.Add(newClient);
                    connectionTypeList.Add("client");
                    logs_remote_server.AppendText("A client is connected. \n");

                    Thread receiveThread = new Thread(new ThreadStart(Receive));
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
                        logs_remote_server.AppendText("Socket has stopped working. \n");
                    }
                }
            }
        }
        private void Receive()
        {
            Socket s = socketList[socketList.Count - 1]; //client that is newly added
            bool connected = true;

            while (!terminating && connected)
            {
                try
                {
                    Byte[] buffer = new Byte[256];
                    s.Receive(buffer);

                    string message = Encoding.Default.GetString(buffer);
                    message = message.Trim('\0');
                    logs_remote_server.AppendText(message + "\n");

                    if (message.Contains("I_am_a_server"))
                    {
                        string server_id = message.Substring(0, 1); // getting first word of the message which is server id.
                        logs_remote_server.AppendText("Server-" + server_id + "is connected\n");
                        serverIDs.Add(server_id);

                        string key = generateKeyForServer();
                        byte[] byte_key = Encoding.Default.GetBytes(key);
                        string hex_key = generateHexStringFromByteArray(byte_key);


                        byte[] AES_128_key = new byte[16];
                        byte[] AES_128_IV = new byte[16];
                        byte[] AES_128_HMAC = new byte[16];

                        Array.Copy(byte_key, 0, AES_128_key, 0, 16);
                        Array.Copy(byte_key, 16, AES_128_IV, 0, 16);
                        Array.Copy(byte_key, 32, AES_128_HMAC, 0, 16);

                        logs_remote_server.AppendText("AES_KEY: " + Encoding.Default.GetString(AES_128_key) + "\n");
                        logs_remote_server.AppendText("AES_IV: " + Encoding.Default.GetString(AES_128_IV) + "\n");
                        logs_remote_server.AppendText("AES_HMAC: " + Encoding.Default.GetString(AES_128_HMAC) + "\n");
                        //logs_remote_server.AppendText("generated session key: " + key + "\n");

                        //string key_conc_signature = key + ":" + signature_string;
                        //logs_remote_server.AppendText(key_conc_signature.Length.ToString() + "\n");
                        byte[] encrypted_key;
                        if (server_id == "1")
                        {
                            encrypted_key = encryptWithRSA(key, 3072, server1_public);
                            AES_128_key_server_1 = AES_128_key;
                            AES_128_IV_server_1 = AES_128_IV;
                            AES_128_HMAC_server_1 = AES_128_HMAC;
                            connectionTypeList[socketList.Count - 1] = "server_1";
                            server_1_connected = true; //!!! SERVER DUSTUGUNDE BUNLARI NASIL GERI FALSE YAPARIZ?

                            server_1_socket = s;
                            server_1_connection_ack = true;
                            // sending server-2 to server-1 is connected
                            if (connectionTypeList.Contains("server_2"))
                            {
                                string msg = "server1_master_server_connected";
                                byte[] msg_b = Encoding.Default.GetBytes(msg);
                                server_2_socket.Send(msg_b);
                            }

                        }
                        else
                        {
                            encrypted_key = encryptWithRSA(key, 3072, server2_public);
                            AES_128_key_server_2 = AES_128_key;
                            AES_128_IV_server_2 = AES_128_IV;
                            AES_128_HMAC_server_2 = AES_128_HMAC;
                            connectionTypeList[socketList.Count - 1] = "server_2";
                            server_2_connected = true; //!!! SERVER DUSTUGUNDE BUNLARI NASIL GERI FALSE YAPARIZ?

                            server_2_connection_ack = true;
                            server_2_socket = s;

                            // sending server-2 to server-1 is connected
                            if (connectionTypeList.Contains("server_1"))
                            {
                                string msg = "server2_master_server_connected";
                                byte[] msg_b = Encoding.Default.GetBytes(msg);
                                server_1_socket.Send(msg_b);
                            }

                        }
                        string encrypted_key_string = Encoding.Default.GetString(encrypted_key);
                        string hex_encrypted_key = generateHexStringFromByteArray(encrypted_key);


                        byte[] signature = signWithRSA(hex_encrypted_key, 3072, masterServer_pub_prv);
                        string signature_string = Encoding.Default.GetString(signature);
                        string hex_signature_string = generateHexStringFromByteArray(signature);

                        string encrypted_key_signature_string = hex_encrypted_key + "::::::::::" + hex_signature_string; // 10 tane :
                        string m = "This_is_your_session_key_sig:" + encrypted_key_signature_string;
                        byte[] encrypted_key_signature_message = Encoding.Default.GetBytes(m);


                        logs_remote_server.AppendText("SIGNATURE: " + hex_signature_string + "\n");
                        logs_remote_server.AppendText("ENC_KEY: " + hex_encrypted_key + "\n");
                        logs_remote_server.AppendText("KEY: " + hex_key + "\n");
                        //logs_remote_server.AppendText("SIGNATURE LENGTH: " + signature_string.Length.ToString() + "\n");
                        //logs_remote_server.AppendText("ENC KEY LENGTH:" + encrypted_key_string.Length.ToString() + "\n");
                        //logs_remote_server.AppendText("ROW MESSAGE LENGTH: " + encrypted_key_signature_message.Length.ToString() + "\n");

                        //logs_remote_server.AppendText("ENC_KEY_BYTES_length: " + Encoding.Default.GetBytes(hex_encrypted_key_string).Length + "\n");

                        s.Send(encrypted_key_signature_message);
                    }
                    // recieving file from clients
                    else if (message.Contains("I will send a file"))
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


                            logs_remote_server.AppendText("ENC_KEY_HEX_LEN: " + encrypted_AES_key.Length + "\n");
                            logs_remote_server.AppendText("ENC_IV_HEX_LEN: " + encrypted_AES_IV.Length + "\n");

                            byte[] AES_key = decryptWithRSA(encrypted_AES_key, 3072, masterServer_pub_prv, true);
                            byte[] AES_IV = decryptWithRSA(encrypted_AES_IV, 3072, masterServer_pub_prv, true);

                            // bunlar hex cunku client encryptledigi keyler hex formatinda
                            string AES_key_hex = Encoding.Default.GetString(AES_key);
                            string AES_IV_hex = Encoding.Default.GetString(AES_IV);

                            string AES_key_string = hexToString(AES_key_hex);
                            string AES_IV_string = hexToString(AES_IV_hex);

                            byte[] AES_key_byte = hexStringToByteArray(AES_key_hex);
                            byte[] AES_IV_byte = hexStringToByteArray(AES_IV_hex);



                            logs_remote_server.AppendText("AES_key_string: " + AES_key_string + "\n");
                            logs_remote_server.AppendText("AES_IV_string: " + AES_IV_string + "\n");

                            logs_remote_server.AppendText("AES_key_HEX: " + AES_key_hex + "\n");
                            logs_remote_server.AppendText("AES_IV_HEX: " + AES_IV_hex + "\n");

                            logs_remote_server.AppendText("KEY_LENGTH:" + AES_key_byte.Length + "\n");
                            logs_remote_server.AppendText("IV_LENGTH:" + AES_IV_byte.Length + "\n");

                            // creatinf dummy file
                            //byte[] dummy = null;
                            //saveByteArrayToFileWithFileStream(dummy, file_name);
                            string filePath = @"C:\Users\emreeren\Desktop\Intro432Proje\Remote_server_432_project\bin\Debug\net5.0-windows\files";
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
                            logs_remote_server.AppendText("\n");
                            logs_remote_server.AppendText("file is recieved in " + chunks_count_string_splitted + " pices(s). \n");
                            logs_remote_server.AppendText("\n");

                            string dummy_string = "start to transfer";
                            byte[] dummy_byte = Encoding.Default.GetBytes(dummy_string);
                            s.Send(dummy_byte);
                            logs_remote_server.AppendText(Encoding.Default.GetString(dummy_byte) + "\n");

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

                                logs_remote_server.AppendText("\n");
                                logs_remote_server.AppendText(i.ToString() + ": " + file_chunk_string + "\n\n"); // generateHexStringFromByteArray(trimmed_file_chunk)
                                logs_remote_server.AppendText("\n");

                                logs_remote_server.AppendText("chunk length: " + trimmed_file_chunk.Length + "\n");

                                logs_remote_server.AppendText("\n");

                                buffer_file_chunk = null;
                            }


                            byte[] encrypted_file = Combine(recieved_chunks_list);

                            logs_remote_server.AppendText("\n");
                            logs_remote_server.AppendText("\n");
                            logs_remote_server.AppendText("\n");
                            logs_remote_server.AppendText("Full encrypted message: " + Encoding.Default.GetString(encrypted_file) + "\n");
                            logs_remote_server.AppendText("Full encrypted length byte: " + encrypted_file.Length + "\n");

                            byte[] decrypted_file = decryptWithAES128(encrypted_file, AES_key_byte, AES_IV_byte);
                            //logs_server.AppendText("FILE: " + Encoding.Default.GetString(decrypted_file) + "\n");
                            saveByteArrayToFileWithFileStream(decrypted_file, file_name);

                            string file_string = generateHexStringFromByteArray(decrypted_file);
                            byte[] file_signature = signWithRSA(file_string, 3072, masterServer_pub_prv);  //file_string                 
                            s.Send(file_signature);
                            logs_remote_server.AppendText("signature length " + file_signature.Length + "\n");


                            byte[] ack_message = new byte[4];
                            s.Receive(ack_message);
                            string m = Encoding.Default.GetString(ack_message).Trim('\0');
                            if (m == "1")
                            {
                                logs_remote_server.AppendText("signature is verified by the client, file is saved \n");
                                not_replicated_files.Add(decrypted_file);
                                not_replicated_file_names.Add(file_name);
                                saveByteArrayToFileWithFileStream(decrypted_file, file_name);
                            }
                            else
                            {
                                logs_remote_server.AppendText("signature is not verified by the client, file is saved \n");
                            }
                        }
                        catch
                        {
                            logs_remote_server.AppendText("something went wrong. \n");
                        }

                    }
                    else if (message.Contains("File_Replication"))
                    {
                        byte[] AES_key = new byte[16];
                        byte[] AES_IV = new byte[16];
                        byte[] HMAC = new byte[16];


                        byte[] message_buffer = new byte[4096];
                        s.Receive(message_buffer);
                        string msg = Encoding.Default.GetString(message_buffer).Trim('\0');

                        int seperator_index = seperateMessage(msg);
                        string sender = msg.Substring(0, seperator_index);
                        msg = msg.Substring(seperator_index + 10);

                        seperator_index = seperateMessage(msg);
                        string file_name = msg.Substring(0, seperator_index);
                        msg = msg.Substring(seperator_index + 10);

                        seperator_index = seperateMessage(msg);
                        string chunks_count_string = msg.Substring(0, seperator_index);
                        msg = msg.Substring(seperator_index + 10);

                        seperator_index = seperateMessage(msg);
                        string recieved_HMAC_file_name_hex = msg.Substring(0, seperator_index);
                        msg = msg.Substring(seperator_index + 10);

                        seperator_index = seperateMessage(msg);
                        string recieved_HMAC_file_hex = msg.Substring(0, seperator_index);

                        if (sender == "server_1")
                        {
                            AES_key = AES_128_key_server_1;
                            AES_IV = AES_128_IV_server_1;
                            HMAC = AES_128_HMAC_server_1;
                        }
                        else
                        {
                            AES_key = AES_128_key_server_2;
                            AES_IV = AES_128_IV_server_2;
                            HMAC = AES_128_HMAC_server_2;
                        }

                        

                        int chunks_count;
                        Int32.TryParse(chunks_count_string, out chunks_count);

                        logs_remote_server.AppendText("Recieved file name: " + file_name + "\n");
                        logs_remote_server.AppendText("\n");
                        logs_remote_server.AppendText("file is recieved in " + chunks_count_string + " pices(s). \n");
                        logs_remote_server.AppendText("\n");


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
                            byte[] trimmed_file_chunk = new byte[j + 1];
                            Array.Copy(buffer_file_chunk, trimmed_file_chunk, j + 1);

                            recieved_chunks_list.Add(trimmed_file_chunk);

                            logs_remote_server.AppendText("\n");
                            logs_remote_server.AppendText(i.ToString() + ": " + file_chunk_string + "\n\n"); // generateHexStringFromByteArray(trimmed_file_chunk)
                            logs_remote_server.AppendText("\n");
                            logs_remote_server.AppendText("chunk length: " + trimmed_file_chunk.Length + "\n");
                            logs_remote_server.AppendText("\n");

                            buffer_file_chunk = null;
                        }

                        byte[] encrypted_file = Combine(recieved_chunks_list);

                        logs_remote_server.AppendText("\n");
                        logs_remote_server.AppendText("\n");
                        logs_remote_server.AppendText("\n");
                        logs_remote_server.AppendText("Full encrypted message: " + Encoding.Default.GetString(encrypted_file) + "\n");
                        logs_remote_server.AppendText("Full encrypted length byte: " + encrypted_file.Length + "\n");

                        byte[] decrypted_file = decryptWithAES128(encrypted_file, AES_key, AES_IV);

                        byte[] HMAC_file = applyHMACwithSHA256(decrypted_file, HMAC);
                        string HMAC_file_hex = generateHexStringFromByteArray(HMAC_file);

                        //Thread.Sleep(300);

                        if (HMAC_file_hex == recieved_HMAC_file_hex)
                        {
                            logs_remote_server.AppendText("Replicated file is verified, and successfully saved. \n");
                            saveByteArrayToFileWithFileStream(decrypted_file, file_name);
                            string ack = "1";
                            byte[] ack_byte = Encoding.Default.GetBytes(ack);
                            s.Send(ack_byte);
                        }
                        else
                        {
                            logs_remote_server.AppendText("Replicated file is not verified. \n");
                            string ack = "0";
                            byte[] ack_byte = Encoding.Default.GetBytes(ack);
                            s.Send(ack_byte);
                        }


                    }

                    else if (message.Contains("server_1_2_connected"))
                    {
                        logs_remote_server.AppendText("Server-1 and Server-2 connected");
                        server_1_server_2_connected = true;
                    }

                    else if (message.Contains("server_1_2_disconnected"))
                    {
                        logs_remote_server.AppendText("Server-1 and Server-2 disconnected");
                        server_1_server_2_connected = false;
                    }

                    else if (message.Contains("Request_Download"))
                    {
                        int seperator_index = seperateMessage(message);
                        string requested_file_name = message.Substring(seperator_index + 10);
                        List<string> uploaded_file_names = getUploadedFileNames();
                        // if server has requested file
                        if (uploaded_file_names.Contains(requested_file_name))
                        {

                            string file_path = @"C:\Users\emreeren\Desktop\Intro432Proje\Remote_server_432_project\bin\Debug\net5.0-windows\files";
                            file_path = file_path + @"\" + requested_file_name;

                            byte[] file_data = File.ReadAllBytes(file_path); // byte[]

                            List<byte[]> file_chunks = splitByteArrayIntoPiece(file_data, 163840); //8912 //20480


                            byte[] ack_msg = Encoding.Default.GetBytes("1::::::::::" + file_chunks.Count.ToString()); // saying client that file is exist.
                            s.Send(ack_msg);

                            for (int i = 0; i < file_chunks.Count; i++)
                            {

                                byte[] encrypted_msg_chunk = file_chunks[i];

                                s.Send(encrypted_msg_chunk);
                                logs_remote_server.AppendText("\n");
                                logs_remote_server.AppendText(i.ToString() + ": " + Encoding.Default.GetString(encrypted_msg_chunk) + "\n\n"); //generateHexStringFromByteArray(encrypted_msg_chunk)
                                logs_remote_server.AppendText("\n");

                                logs_remote_server.AppendText("chunk length: " + encrypted_msg_chunk.Length + "\n");
                                logs_remote_server.AppendText("\n");
                                Thread.Sleep(100);

                            }
                            Thread.Sleep(100);
                            string file_data_hex = generateHexStringFromByteArray(file_data);
                            byte[] file_signature = signWithRSA(file_data_hex, 3072, masterServer_pub_prv);
                            s.Send(file_signature);
                        }
                        else
                        {
                            byte[] ack_msg = Encoding.Default.GetBytes("0"); // saying client that file is not exist.
                            s.Send(ack_msg);
                        }

                    }

                    if (server_1_connected && server_2_connected && server_1_server_2_connected)
                    {
                        try
                        {
                            int server_1_index = connectionTypeList.IndexOf("server_1");
                            int server_2_index = connectionTypeList.IndexOf("server_2");
                            //server_1_socket = socketList[server_1_index];
                            //server_2_socket = socketList[server_2_index];

                            while (not_replicated_files.Count > 0 && not_replicated_file_names.Count > 0)
                            {

                                byte[] file_data = not_replicated_files[0];
                                string file_name = not_replicated_file_names[0];

                                bool isReplicated_server1 = distributeFile(server_1_socket, file_data, file_name, "master_server", "server_1");
                                bool isReplicated_server2 = distributeFile(server_2_socket, file_data, file_name, "master_server", "server_2");

                                if (isReplicated_server1 && isReplicated_server2)
                                {
                                    not_replicated_files.RemoveAt(0);
                                    not_replicated_file_names.RemoveAt(0);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            logs_remote_server.AppendText(e.ToString() + "\n");
                        }
                    }

                    if (server_1_connection_ack)
                    {
                        if (connectionTypeList.Contains("server_2"))
                        {
                            string msg = "server1_master_server_connected";
                            byte[] msg_b = Encoding.Default.GetBytes(msg);
                            server_2_socket.Send(msg_b);
                        }
                        //server_1_connection_ack = false;

                    }
                    if (server_2_connection_ack)
                    {
                        if (connectionTypeList.Contains("server_1"))
                        {
                            string msg = "server2_master_server_connected";
                            byte[] msg_b = Encoding.Default.GetBytes(msg);
                            server_1_socket.Send(msg_b);
                        }
                        //server_2_connection_ack = false;
                    }

                }
                catch
                {
                    if (connectionTypeList[socketList.Count - 1] == "server_1")
                    {
                        logs_remote_server.AppendText("Server-1 is disconnected. \n");
                        server_1_connected = false;
                        connectionTypeList.Remove("server_1");


                        if (connectionTypeList.Contains("server_2"))
                        {
                            string master_message = "server1_master_server_disconnected";
                            byte[] master_buffer = Encoding.Default.GetBytes(master_message);
                            server_2_socket.Send(master_buffer);
                        }
                    }

                    else if (connectionTypeList[socketList.Count - 1] == "server_2")
                    {
                        logs_remote_server.AppendText("Server-2 is disconnected. \n");
                        server_2_connected = false;
                        connectionTypeList.Remove("server_2");

                        if (connectionTypeList.Contains("server_1"))
                        {
                            string master_message = "server2_master_server_disconnected";
                            byte[] master_buffer = Encoding.Default.GetBytes(master_message);
                            server_1_socket.Send(master_buffer);
                        }
                    }
                    else
                    {
                        logs_remote_server.AppendText("A client is disconnected. \n");
                    }

                    s.Close();
                    socketList.Remove(s);
                    connected = false;
                }
            }
        }

        /*
        private void fileReplication()
        {
            while (listening)
            {
                if (server_1_connected && server_2_connected && server_1_server_2_connected)
                {
                    try
                    {
                        int server_1_index = connectionTypeList.IndexOf("server_1");
                        int server_2_index = connectionTypeList.IndexOf("server_2");
                        //server_1_socket = socketList[server_1_index];
                        //server_2_socket = socketList[server_2_index];

                        while (not_replicated_files.Count > 0 && not_replicated_file_names.Count > 0)
                        {

                            byte[] file_data = not_replicated_files[0];
                            string file_name = not_replicated_file_names[0];

                            bool isReplicated_server1 = distributeFile(server_1_socket, file_data, file_name, "master_server", "server_1");
                            bool isReplicated_server2 = distributeFile(server_2_socket, file_data, file_name, "master_server", "server_2");

                            if (isReplicated_server1 && isReplicated_server2)
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
                        logs_remote_server.AppendText(e.ToString() + "\n");
                    }
                }
            }
        }
        */
    }
}

