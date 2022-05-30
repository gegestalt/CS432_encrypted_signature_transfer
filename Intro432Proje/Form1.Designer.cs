
namespace Intro432Proje
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.connect_button = new System.Windows.Forms.Button();
            this.send_button = new System.Windows.Forms.Button();
            this.ip_textBox = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.port_textBox = new System.Windows.Forms.TextBox();
            this.logs = new System.Windows.Forms.RichTextBox();
            this.disconnect_button = new System.Windows.Forms.Button();
            this.browse_textBox = new System.Windows.Forms.TextBox();
            this.browse_button = new System.Windows.Forms.Button();
            this.server1_radioButton = new System.Windows.Forms.RadioButton();
            this.server2_radioButton = new System.Windows.Forms.RadioButton();
            this.masterServer_radioButton = new System.Windows.Forms.RadioButton();
            this.downloadFile_button1 = new System.Windows.Forms.Button();
            this.downloaded_filename_textBox = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // connect_button
            // 
            this.connect_button.Location = new System.Drawing.Point(113, 73);
            this.connect_button.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.connect_button.Name = "connect_button";
            this.connect_button.Size = new System.Drawing.Size(178, 22);
            this.connect_button.TabIndex = 0;
            this.connect_button.Text = "Connect";
            this.connect_button.UseVisualStyleBackColor = true;
            this.connect_button.Click += new System.EventHandler(this.connect_button_Click);
            // 
            // send_button
            // 
            this.send_button.Enabled = false;
            this.send_button.Location = new System.Drawing.Point(113, 219);
            this.send_button.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.send_button.Name = "send_button";
            this.send_button.Size = new System.Drawing.Size(121, 22);
            this.send_button.TabIndex = 1;
            this.send_button.Text = "Send";
            this.send_button.UseVisualStyleBackColor = true;
            this.send_button.Click += new System.EventHandler(this.send_button_Click);
            // 
            // ip_textBox
            // 
            this.ip_textBox.Location = new System.Drawing.Point(113, 12);
            this.ip_textBox.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.ip_textBox.Name = "ip_textBox";
            this.ip_textBox.Size = new System.Drawing.Size(179, 23);
            this.ip_textBox.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(71, 14);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(20, 15);
            this.label1.TabIndex = 3;
            this.label1.Text = "IP:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(71, 42);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(35, 15);
            this.label2.TabIndex = 4;
            this.label2.Text = "Port: ";
            // 
            // port_textBox
            // 
            this.port_textBox.Location = new System.Drawing.Point(113, 42);
            this.port_textBox.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.port_textBox.Name = "port_textBox";
            this.port_textBox.Size = new System.Drawing.Size(179, 23);
            this.port_textBox.TabIndex = 5;
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(363, 11);
            this.logs.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.logs.Name = "logs";
            this.logs.Size = new System.Drawing.Size(325, 290);
            this.logs.TabIndex = 6;
            this.logs.Text = "";
            // 
            // disconnect_button
            // 
            this.disconnect_button.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.disconnect_button.Location = new System.Drawing.Point(585, 305);
            this.disconnect_button.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.disconnect_button.Name = "disconnect_button";
            this.disconnect_button.Size = new System.Drawing.Size(103, 31);
            this.disconnect_button.TabIndex = 7;
            this.disconnect_button.Text = "Disconnect";
            this.disconnect_button.UseVisualStyleBackColor = false;
            this.disconnect_button.Click += new System.EventHandler(this.button1_Click);
            // 
            // browse_textBox
            // 
            this.browse_textBox.Enabled = false;
            this.browse_textBox.Location = new System.Drawing.Point(11, 191);
            this.browse_textBox.Name = "browse_textBox";
            this.browse_textBox.Size = new System.Drawing.Size(294, 23);
            this.browse_textBox.TabIndex = 9;
            // 
            // browse_button
            // 
            this.browse_button.Location = new System.Drawing.Point(302, 191);
            this.browse_button.Name = "browse_button";
            this.browse_button.Size = new System.Drawing.Size(55, 23);
            this.browse_button.TabIndex = 10;
            this.browse_button.Text = "Browse";
            this.browse_button.UseVisualStyleBackColor = true;
            this.browse_button.Click += new System.EventHandler(this.browse_button_Click);
            // 
            // server1_radioButton
            // 
            this.server1_radioButton.AutoSize = true;
            this.server1_radioButton.Location = new System.Drawing.Point(12, 118);
            this.server1_radioButton.Name = "server1_radioButton";
            this.server1_radioButton.Size = new System.Drawing.Size(66, 19);
            this.server1_radioButton.TabIndex = 11;
            this.server1_radioButton.TabStop = true;
            this.server1_radioButton.Text = "Server 1";
            this.server1_radioButton.UseVisualStyleBackColor = true;
            // 
            // server2_radioButton
            // 
            this.server2_radioButton.AutoSize = true;
            this.server2_radioButton.Location = new System.Drawing.Point(12, 143);
            this.server2_radioButton.Name = "server2_radioButton";
            this.server2_radioButton.Size = new System.Drawing.Size(66, 19);
            this.server2_radioButton.TabIndex = 12;
            this.server2_radioButton.TabStop = true;
            this.server2_radioButton.Text = "Server 2";
            this.server2_radioButton.UseVisualStyleBackColor = true;
            // 
            // masterServer_radioButton
            // 
            this.masterServer_radioButton.AutoSize = true;
            this.masterServer_radioButton.Location = new System.Drawing.Point(12, 166);
            this.masterServer_radioButton.Name = "masterServer_radioButton";
            this.masterServer_radioButton.Size = new System.Drawing.Size(96, 19);
            this.masterServer_radioButton.TabIndex = 13;
            this.masterServer_radioButton.TabStop = true;
            this.masterServer_radioButton.Text = "Master Server";
            this.masterServer_radioButton.UseVisualStyleBackColor = true;
            // 
            // downloadFile_button1
            // 
            this.downloadFile_button1.Location = new System.Drawing.Point(261, 289);
            this.downloadFile_button1.Name = "downloadFile_button1";
            this.downloadFile_button1.Size = new System.Drawing.Size(96, 23);
            this.downloadFile_button1.TabIndex = 15;
            this.downloadFile_button1.Text = "Download";
            this.downloadFile_button1.UseVisualStyleBackColor = true;
            this.downloadFile_button1.Click += new System.EventHandler(this.downloadFile_button1_Click);
            // 
            // downloaded_filename_textBox
            // 
            this.downloaded_filename_textBox.Location = new System.Drawing.Point(11, 289);
            this.downloaded_filename_textBox.Name = "downloaded_filename_textBox";
            this.downloaded_filename_textBox.Size = new System.Drawing.Size(244, 23);
            this.downloaded_filename_textBox.TabIndex = 14;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 271);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(185, 15);
            this.label3.TabIndex = 16;
            this.label3.Text = "Enter file name to be downloaded";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(700, 338);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.downloadFile_button1);
            this.Controls.Add(this.downloaded_filename_textBox);
            this.Controls.Add(this.masterServer_radioButton);
            this.Controls.Add(this.server2_radioButton);
            this.Controls.Add(this.server1_radioButton);
            this.Controls.Add(this.browse_button);
            this.Controls.Add(this.browse_textBox);
            this.Controls.Add(this.disconnect_button);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.port_textBox);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.ip_textBox);
            this.Controls.Add(this.send_button);
            this.Controls.Add(this.connect_button);
            this.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.Name = "Form1";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button connect_button;
        private System.Windows.Forms.Button send_button;
        private System.Windows.Forms.TextBox ip_textBox;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox port_textBox;
        private System.Windows.Forms.RichTextBox logs;
        private System.Windows.Forms.Button disconnect_button;
        private System.Windows.Forms.TextBox browse_textBox;
        private System.Windows.Forms.Button browse_button;
        private System.Windows.Forms.RadioButton server1_radioButton;
        private System.Windows.Forms.RadioButton server2_radioButton;
        private System.Windows.Forms.RadioButton masterServer_radioButton;
        private System.Windows.Forms.Button downloadFile_button1;
        private System.Windows.Forms.TextBox downloaded_filename_textBox;
        private System.Windows.Forms.Label label3;
    }
}

