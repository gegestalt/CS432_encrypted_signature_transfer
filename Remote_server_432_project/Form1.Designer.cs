
namespace Remote_server_432_project
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
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.port_textBox = new System.Windows.Forms.TextBox();
            this.listen_button = new System.Windows.Forms.Button();
            this.logs_remote_server = new System.Windows.Forms.RichTextBox();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(130, 16);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(83, 15);
            this.label1.TabIndex = 0;
            this.label1.Text = "Remote Server";
            this.label1.Click += new System.EventHandler(this.label1_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(29, 50);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(114, 15);
            this.label2.TabIndex = 1;
            this.label2.Text = "Remote Server Port: ";
            // 
            // port_textBox
            // 
            this.port_textBox.Location = new System.Drawing.Point(160, 50);
            this.port_textBox.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.port_textBox.Name = "port_textBox";
            this.port_textBox.Size = new System.Drawing.Size(177, 23);
            this.port_textBox.TabIndex = 2;
            // 
            // listen_button
            // 
            this.listen_button.Location = new System.Drawing.Point(29, 88);
            this.listen_button.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.listen_button.Name = "listen_button";
            this.listen_button.Size = new System.Drawing.Size(308, 22);
            this.listen_button.TabIndex = 3;
            this.listen_button.Text = "Listen";
            this.listen_button.UseVisualStyleBackColor = true;
            this.listen_button.Click += new System.EventHandler(this.button1_Click);
            // 
            // logs_remote_server
            // 
            this.logs_remote_server.Location = new System.Drawing.Point(29, 145);
            this.logs_remote_server.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.logs_remote_server.Name = "logs_remote_server";
            this.logs_remote_server.Size = new System.Drawing.Size(308, 168);
            this.logs_remote_server.TabIndex = 4;
            this.logs_remote_server.Text = "";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(396, 338);
            this.Controls.Add(this.logs_remote_server);
            this.Controls.Add(this.listen_button);
            this.Controls.Add(this.port_textBox);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.Name = "Form1";
            this.Text = "Form1";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox port_textBox;
        private System.Windows.Forms.Button listen_button;
        private System.Windows.Forms.RichTextBox logs_remote_server;
    }
}

