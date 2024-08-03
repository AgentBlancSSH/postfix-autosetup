Automatic Postfix Server Configuration Script

This script automatically configures a Postfix mail server on a Linux server. It is designed to be user-friendly, even for beginners,
and includes several features to adapt to different environments.

Key Features

Python 3 Installation Check: If Python 3 is not installed, the script automatically installs it before proceeding.
Prerequisite Check: The script verifies and installs the necessary packages for Postfix.
Multi-Distribution Support: The script detects the Linux distribution (Debian/Ubuntu or CentOS/Red Hat) and adjusts commands accordingly.
User Input Validation: The script validates the hostname and other user-provided information.
Configuration File Backup: Critical files are automatically backed up before any modifications are made.
Automatic DKIM Record Generation: The script generates the DKIM public key and includes it directly in the final report.
Verbose Mode: Option to display more detailed information about the script's steps.
Command-Line Options: You can pre-specify certain options for a more automated operation.
Prerequisites

Before starting, make sure you have:

A Linux server: The script is compatible with Ubuntu, Debian, CentOS, and Red Hat.
Root access or sudo privileges on the server.
A domain name that you can configure to send emails (e.g., your-domain.com).


Installation

Download the Script
Download the setup_postfix_complete.py script to your server.

bash
wget <link-to-script> -O setup_postfix_complete.py
Grant Execution Rights
Ensure the script is executable:

bash
chmod +x setup_postfix_complete.py
Run the Script
To launch the script, use the following command:

bash
sudo python3 setup_postfix_complete.py
Command-Line Options
You can pass options when running the script to automate some inputs:

--hostname: Specify the mail server hostname. For example:

bash
sudo python3 setup_postfix_complete.py --hostname mail.your-domain.com
--external-domain: Indicate if the domain is managed by an external provider (yes or no). 

For example:

bash
sudo python3 setup_postfix_complete.py --external-domain yes
--verbose: Enable verbose mode to see more details on each step:

bash
sudo python3 setup_postfix_complete.py --verbose
Monitor the Configuration
The script generates a real-time log file. You can monitor the script's execution here: /tmp/postfix_setup_log.txt.

Final Report

Once the configuration is complete, the script generates a report containing essential information, 
including the necessary DNS records for SPF, DKIM, and DMARC. 
This report is saved here: /tmp/postfix_setup_report.txt.

DNS Record Configuration
If your domain is managed by an external provider, add the provided SPF, DKIM, and DMARC records to your domain's DNS configuration.

Verify Operation
To ensure everything is working correctly, you can check Postfix logs:

bash
tail -f /var/log/mail.log
Frequently Asked Questions (FAQ)

What should I do if I encounter an error?
Check the log file for more details. If the error persists, seek help online or consult a system administrator.
How can I further customize the configuration?
After running the script, you can modify the /etc/postfix/main.cf file to tailor the Postfix configuration.
How do I know if my server is properly configured?
You can send a test email and use online services like Mail-tester.com to verify that your emails are correctly configured and not marked as spam.


Conclusion

This script allows you to automatically and securely configure a Postfix mail server, even if you are a beginner. By following these instructions, you can quickly set up a functional server. Feel free to customize the script to your needs and review the final report to ensure everything is correctly configured.
