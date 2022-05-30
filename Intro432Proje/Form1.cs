using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;

using System.Net;
using System.IO;
using System.Threading;

namespace Intro432Proje
{
    public partial class Form1 : Form
    {
        bool terminating = false;
        bool connected = false;
        Socket clientSocket;

        string server1_public;
        string masterServer_public;
        string server2_public;

        byte[] AES_128_key = new byte[16];
        byte[] AES_128_IV = new byte[16];

        string file_path;
        string file_name;


        byte[] file_name_byte;
        byte[] file_data;

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
            server1_public = readFile("Server1_pub.txt");
            masterServer_public = readFile("MasterServer_pub.txt");
            server2_public = readFile("Server2_pub.txt");
        }
        void generateKeyForFileTransfer()
        {
            byte[] key_byte = new Byte[32];

            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
            random.GetBytes(key_byte);

            Array.Copy(key_byte, 0, AES_128_key, 0, 16);
            Array.Copy(key_byte, 16, AES_128_IV, 0, 16);
        }

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
            string filePath = @"CC:\Users\guney\Downloads\revised_432_test\Intro432Proje\Intro432Proje\bin\Debug\net5.0-windows\files";
            filePath = filePath + @"\" + fileName;
            //using var stream = File.Create(filePath);
            //stream.Write(data, 0, data.Length);

            using (Stream file = File.OpenWrite(filePath))
            {
                file.Write(data, 0, data.Length);
            }
        }

        public Form1()
        {
            InitializeComponent();
        }

        private void connect_button_Click(object sender, EventArgs e)
        {
            clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            string ip = ip_textBox.Text;
            string port_num = port_textBox.Text;
            //string ip = "127.0.0.1";
            //string port_num = "11";
            int portnum;
            if (Int32.TryParse(port_num, out portnum))
            {
                try
                {
                        clientSocket.Connect(ip, portnum);
                        //connect_button.Enabled = false;
                        connected = true;
                        logs.AppendText("A client has connected to server. \n");
                        getKeysFromFile();
                }
                catch 
                {

                    logs.AppendText("Connection could not established. \n");
                }
               
            }
            else
            {
                logs.AppendText("Check the port number. \n");
            }

        }
        private void Receive()
        {
            while (connected)
            {
                try
                {
                    Byte[] buffer = new Byte[64];
                    clientSocket.Receive(buffer);

                    string message = Encoding.Default.GetString(buffer);
                    message = message.Substring(0, message.IndexOf("\0"));
                    logs.AppendText(message + "\n");
                }
                catch
                {
                    if (!terminating)
                    {
                        logs.AppendText("Connection has lost with the server. \n");
                    }

                    clientSocket.Close();
                    connected = false;
                }
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            clientSocket.Disconnect(connected = false);
            clientSocket.Close();
            if (!clientSocket.Connected)
            {
                logs.AppendText("A client has disconnected \n");
            }
            
            connected = false;
            terminating = true;
            connect_button.Enabled = true;
            
        }

        private void browse_button_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();

            if (ofd.ShowDialog() == DialogResult.OK)
            {
                browse_textBox.Text = ofd.FileName;
             
                file_path = ofd.FileName; //string
                file_name = System.IO.Path.GetFileName(file_path); //string
                file_name_byte = Encoding.ASCII.GetBytes(file_name); // byte[]

                file_data = File.ReadAllBytes(file_path); // byte[]

                //logs.AppendText("file_data:" + Encoding.Default.GetString(file_data) + "\n");

                send_button.Enabled = true;

                generateKeyForFileTransfer();

                string filePath = @"C: \Users\guney\Downloads";
                filePath = filePath + @"\" + file_name;
                using var stream = File.Create(filePath);
                stream.Write(file_data, 0, file_data.Length);
            }

        }

        private void send_button_Click(object sender, EventArgs e)
        {
            string used_server_key;
            string request = "I will send a file";
            byte[] request_byte = Encoding.Default.GetBytes(request);
            clientSocket.Send(request_byte);


            string AES_key_string = Encoding.Default.GetString(AES_128_key);
            string AES_IV_string = Encoding.Default.GetString(AES_128_IV);

            string AES_key_hex= generateHexStringFromByteArray(AES_128_key);
            string AES_IV_hex= generateHexStringFromByteArray(AES_128_IV);

            byte[] encrypted_AES_key;
            byte[] encrypted_AES_IV;
            if (server1_radioButton.Checked)
            {
                used_server_key = server1_public;
            }
            else if (server2_radioButton.Checked)
            {
                used_server_key = server2_public;
            }
            else
            {
                used_server_key = masterServer_public;
            }

            encrypted_AES_key = encryptWithRSA(AES_key_hex, 3072, used_server_key);
            encrypted_AES_IV = encryptWithRSA(AES_IV_hex, 3072, used_server_key);

            string encrypted_AES_key_hex = generateHexStringFromByteArray(encrypted_AES_key);
            string encrypted_AES_IV_hex = generateHexStringFromByteArray(encrypted_AES_IV);

            logs.AppendText("ENC_key_HEX_LEN: " + encrypted_AES_key_hex.Length + "\n"); // burasi vardi
            logs.AppendText("ENC_IV_HEX_LEN: " + encrypted_AES_IV_hex.Length + "\n");


            string message = file_name + "::::::::::" + encrypted_AES_key_hex + "::::::::::" + encrypted_AES_IV_hex + "::::::::::" + "ALAMK";
            byte[] name_and_keys = Encoding.Default.GetBytes(message);
            clientSocket.Send(name_and_keys);


            logs.AppendText("AES_key: " + Encoding.Default.GetString(AES_128_key) + "\n");
            logs.AppendText("AES_IV: " + Encoding.Default.GetString(AES_128_IV) + "\n");

            logs.AppendText("AES_key_HEX: " + AES_key_hex + "\n");
            logs.AppendText("AES_IV_HEX: " + AES_IV_hex + "\n");

            logs.AppendText("KEY_LENGTH: " + AES_128_key.Length + "\n");
            logs.AppendText("IV_LENGTH: " + AES_128_IV.Length + "\n");

            //encrypting file
            byte[] encrypted_file = encryptWithAES128(file_data, AES_128_key, AES_128_IV);
            string encrypted_file_data_string = Encoding.Default.GetString(encrypted_file);
            List<byte[]> encrypted_message_chunks = splitByteArrayIntoPiece(encrypted_file, 163840); //8912 //20480

            byte[] decrypted_file = decryptWithAES128(encrypted_file, AES_128_key, AES_128_IV);
            string decrypted_file_data_string = Encoding.Default.GetString(decrypted_file);

            string chunk_count = encrypted_message_chunks.Count + "::::::::::";
            byte[] msg = Encoding.Default.GetBytes(chunk_count);
            clientSocket.Send(msg);
            logs.AppendText("\n");
            logs.AppendText("file is send in " + encrypted_message_chunks.Count + " pices(s). \n");
            logs.AppendText("\n");


            Byte[] ack_buffer = new Byte[64];
            clientSocket.Receive(ack_buffer);
            string ack_string = Encoding.Default.GetString(ack_buffer).Trim('\0');
            logs.AppendText(ack_string + "\n");

            if (ack_string.Contains("start to transfer"))
            {
                for (int i = 0; i < encrypted_message_chunks.Count; i++)
                {
                    
                    byte[] encrypted_msg_chunk = encrypted_message_chunks[i];

                    clientSocket.Send(encrypted_msg_chunk);
                    logs.AppendText("\n");
                    logs.AppendText(i.ToString() + ": " + Encoding.Default.GetString(encrypted_msg_chunk) + "\n\n"); //generateHexStringFromByteArray(encrypted_msg_chunk)
                    logs.AppendText("\n");

                    logs.AppendText("chunk length: " + encrypted_msg_chunk.Length + "\n");
                    logs.AppendText("\n");
                    Thread.Sleep(100);
                }
            }

            logs.AppendText("\n");
            logs.AppendText("\n");
            logs.AppendText("\n");
            logs.AppendText("Full encrypted message: " + encrypted_file_data_string + "\n");
            logs.AppendText("Full encrypted length byte: " + encrypted_file.Length + "\n");
            //logs.AppendText("FILE: " + file_data_string + "\n");

            byte[] file_signature_buffer = new byte[384];
            clientSocket.Receive(file_signature_buffer);
            //string file_signature_string = Encoding.Default.GetString(file_signature_buffer).Trim('\0');
            //byte[] file_signature =Encoding.Default.GetBytes(file_signature_string);
            string file_data_string = generateHexStringFromByteArray(file_data); //Encoding.Default.GetString(file_data);

            if (verifyWithRSA(file_data_string, 3072, used_server_key, file_signature_buffer)) //file_data_string
            {
                logs.AppendText("File was recieved succesfully by the server, and verified.\n");
                string m = "1";
                byte[] m_byte = Encoding.Default.GetBytes(m);
                clientSocket.Send(m_byte);
            }
            else
            {
                logs.AppendText("File was not recieved succesfully by the server, and verified.\n");
                string m = "0";
                byte[] m_byte = Encoding.Default.GetBytes(m);
                clientSocket.Send(m_byte);
            }


        }

        private void downloadFile_button1_Click(object sender, EventArgs e)
        {
            string used_server_key;
            string request = "Request_Download" + "::::::::::" + downloaded_filename_textBox.Text;
            byte[] request_byte = Encoding.Default.GetBytes(request);
            clientSocket.Send(request_byte);


            if (server1_radioButton.Checked)
            {
                used_server_key = server1_public;
            }
            else if (server2_radioButton.Checked)
            {
                used_server_key = server2_public;
            }
            else
            {
                used_server_key = masterServer_public;
            }


            byte[] buffer = new byte[128];
            clientSocket.Receive(buffer);
            string ack = Encoding.Default.GetString(buffer).Trim('\0');
            if (ack[0] == '1') // server said that, file exists in the server
            {
                int seperator_index = seperateMessage(ack);
                string chunk_count_string = ack.Substring(seperator_index + 10);

                int chunks_count;
                Int32.TryParse(chunk_count_string, out chunks_count);
                logs.AppendText("\n");
                logs.AppendText("file is recieved in " + chunk_count_string + " pices(s). \n");
                logs.AppendText("\n");

                List<string> file_chunks = new List<string>();

                // recieving files in 2048 byte chunks:
                List<byte[]> recieved_chunks_list = new List<byte[]>();
                for (int i = 0; i < chunks_count; i++)
                {

                    Byte[] buffer_file_chunk = new Byte[163840];
                    clientSocket.Receive(buffer_file_chunk);
                    string file_chunk_string = Encoding.Default.GetString(buffer_file_chunk).Trim('\0');

                    // removing dummy bytes from buffer_file_chunk
                    int j = buffer_file_chunk.Length - 1;
                    while (buffer_file_chunk[j] == 0)
                        --j;
                    // now foo[i] is the last non-zero byte
                    byte[] trimmed_file_chunk = new byte[j + 1];
                    Array.Copy(buffer_file_chunk, trimmed_file_chunk, j + 1);

                    recieved_chunks_list.Add(trimmed_file_chunk);

                    logs.AppendText(i.ToString() + ": " + file_chunk_string + "\n\n"); // generateHexStringFromByteArray(trimmed_file_chunk)
                    logs.AppendText("chunk length: " + trimmed_file_chunk.Length + "\n");
                    logs.AppendText("\n");

                    buffer_file_chunk = null;
                }
                byte[] signature_buffer = new byte[384];
                clientSocket.Receive(signature_buffer);

                byte[] file = Combine(recieved_chunks_list);

                string file_hex = generateHexStringFromByteArray(file);
                if (verifyWithRSA(file_hex, 3072, used_server_key,signature_buffer))
                {
                    logs.AppendText("File is verified and saved to the files folder\n");
                    saveByteArrayToFileWithFileStream(file, downloaded_filename_textBox.Text);
                }
                else
                {
                    logs.AppendText("File is not verified. \n");
                }


            }
            else // server said that, file doesnt exist in the server
            {
                logs.AppendText("Requested file doesn't exist in the server. \n");
            }

        }
    }
}

/*
// send how many parts the file will be divided into 
string chunk_count = encrypted_message_chunks.Count + "::::::::::";
byte[] msg = Encoding.Default.GetBytes(chunk_count);
clientSocket.Send(msg);
logs.AppendText("\n");
logs.AppendText("file is send in " + encrypted_message_chunks.Count + " pices(s). \n");
logs.AppendText("\n");

TcpClient tcpClient = new TcpClient("127.0.0.1", 11);
StreamWriter sWriter = new StreamWriter(tcpClient.GetStream());

sWriter.WriteLine(encrypted_file.Length.ToString());
sWriter.Flush();

sWriter.WriteLine(file_name);
sWriter.Flush();

logs.AppendText("Sending file\n");
tcpClient.Client.SendFile(file_name);
*/