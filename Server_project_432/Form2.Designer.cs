
namespace Server_project_432
{
    partial class Form2
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
            this.label1 = new System.Windows.Forms.Label();
            this.server_port_textBox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.listen_button = new System.Windows.Forms.Button();
            this.logs_server = new System.Windows.Forms.RichTextBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.connect_rmt_btn = new System.Windows.Forms.Button();
            this.rmt_port = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.rmt_ip = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.server2_connect_button = new System.Windows.Forms.Button();
            this.server2_port_textBox = new System.Windows.Forms.TextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.server2_IP_textBox = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(114, 12);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(71, 20);
            this.label1.TabIndex = 0;
            this.label1.Text = "Server #1";
            // 
            // server_port_textBox
            // 
            this.server_port_textBox.Location = new System.Drawing.Point(59, 53);
            this.server_port_textBox.Name = "server_port_textBox";
            this.server_port_textBox.Size = new System.Drawing.Size(174, 27);
            this.server_port_textBox.TabIndex = 1;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(11, 57);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(42, 20);
            this.label2.TabIndex = 2;
            this.label2.Text = "Port: ";
            // 
            // listen_button
            // 
            this.listen_button.Location = new System.Drawing.Point(59, 87);
            this.listen_button.Name = "listen_button";
            this.listen_button.Size = new System.Drawing.Size(175, 29);
            this.listen_button.TabIndex = 3;
            this.listen_button.Text = "Listen";
            this.listen_button.UseVisualStyleBackColor = true;
            this.listen_button.Click += new System.EventHandler(this.listen_button_Click);
            // 
            // logs_server
            // 
            this.logs_server.Location = new System.Drawing.Point(269, 49);
            this.logs_server.Name = "logs_server";
            this.logs_server.Size = new System.Drawing.Size(649, 373);
            this.logs_server.TabIndex = 4;
            this.logs_server.Text = "";
            this.logs_server.TextChanged += new System.EventHandler(this.logs_server_TextChanged);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.connect_rmt_btn);
            this.groupBox1.Controls.Add(this.rmt_port);
            this.groupBox1.Controls.Add(this.label4);
            this.groupBox1.Controls.Add(this.rmt_ip);
            this.groupBox1.Controls.Add(this.label3);
            this.groupBox1.Location = new System.Drawing.Point(11, 121);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(250, 156);
            this.groupBox1.TabIndex = 5;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Connect to Master Server";
            // 
            // connect_rmt_btn
            // 
            this.connect_rmt_btn.BackColor = System.Drawing.SystemColors.GradientActiveCaption;
            this.connect_rmt_btn.Location = new System.Drawing.Point(2, 112);
            this.connect_rmt_btn.Name = "connect_rmt_btn";
            this.connect_rmt_btn.Size = new System.Drawing.Size(237, 29);
            this.connect_rmt_btn.TabIndex = 10;
            this.connect_rmt_btn.Text = "Connect";
            this.connect_rmt_btn.UseVisualStyleBackColor = false;
            this.connect_rmt_btn.Click += new System.EventHandler(this.connect_rmt_btn_Click);
            // 
            // rmt_port
            // 
            this.rmt_port.Location = new System.Drawing.Point(118, 67);
            this.rmt_port.Name = "rmt_port";
            this.rmt_port.Size = new System.Drawing.Size(119, 27);
            this.rmt_port.TabIndex = 9;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(3, 71);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(91, 20);
            this.label4.TabIndex = 8;
            this.label4.Text = "Master Port: ";
            // 
            // rmt_ip
            // 
            this.rmt_ip.Location = new System.Drawing.Point(118, 29);
            this.rmt_ip.Name = "rmt_ip";
            this.rmt_ip.Size = new System.Drawing.Size(121, 27);
            this.rmt_ip.TabIndex = 7;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(3, 33);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(118, 20);
            this.label3.TabIndex = 6;
            this.label3.Text = "Master Server IP:";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.server2_connect_button);
            this.groupBox2.Controls.Add(this.server2_port_textBox);
            this.groupBox2.Controls.Add(this.label5);
            this.groupBox2.Controls.Add(this.server2_IP_textBox);
            this.groupBox2.Controls.Add(this.label6);
            this.groupBox2.Location = new System.Drawing.Point(11, 283);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(250, 156);
            this.groupBox2.TabIndex = 6;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Connect to Server-2";
            // 
            // server2_connect_button
            // 
            this.server2_connect_button.BackColor = System.Drawing.SystemColors.GradientActiveCaption;
            this.server2_connect_button.Location = new System.Drawing.Point(2, 112);
            this.server2_connect_button.Name = "server2_connect_button";
            this.server2_connect_button.Size = new System.Drawing.Size(237, 29);
            this.server2_connect_button.TabIndex = 10;
            this.server2_connect_button.Text = "Connect";
            this.server2_connect_button.UseVisualStyleBackColor = false;
            this.server2_connect_button.Click += new System.EventHandler(this.server2_connect_button_Click);
            // 
            // server2_port_textBox
            // 
            this.server2_port_textBox.Location = new System.Drawing.Point(118, 67);
            this.server2_port_textBox.Name = "server2_port_textBox";
            this.server2_port_textBox.Size = new System.Drawing.Size(119, 27);
            this.server2_port_textBox.TabIndex = 9;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(3, 69);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(101, 20);
            this.label5.TabIndex = 8;
            this.label5.Text = "Server-2 Port: ";
            // 
            // server2_IP_textBox
            // 
            this.server2_IP_textBox.Location = new System.Drawing.Point(118, 29);
            this.server2_IP_textBox.Name = "server2_IP_textBox";
            this.server2_IP_textBox.Size = new System.Drawing.Size(121, 27);
            this.server2_IP_textBox.TabIndex = 7;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(3, 32);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(83, 20);
            this.label6.TabIndex = 6;
            this.label6.Text = "Server-2 IP:";
            // 
            // Form2
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(931, 517);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.logs_server);
            this.Controls.Add(this.listen_button);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.server_port_textBox);
            this.Controls.Add(this.label1);
            this.Name = "Form2";
            this.Text = "Form1";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox server_port_textBox;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button listen_button;
        private System.Windows.Forms.RichTextBox logs_server;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Button connect_rmt_btn;
        private System.Windows.Forms.TextBox rmt_port;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox rmt_ip;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.Button server2_connect_button;
        private System.Windows.Forms.TextBox server2_port_textBox;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox server2_IP_textBox;
        private System.Windows.Forms.Label label6;
    }
}

