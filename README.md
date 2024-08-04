Automatic Postfix Server Configuration Script


This script automates the configuration of a Postfix mail server on a Linux system, making it accessible even for beginners. It includes features that adapt to different environments and ensures secure email sending.

Key Features

Root Access: Requires root or sudo privileges for execution.
Linux Distribution Detection: Automatically detects the Linux distribution (Debian/Ubuntu or CentOS/Red Hat) and adjusts 
commands accordingly.

Prerequisite Check: 

Verifies and installs all necessary packages for Postfix, including Postfix itself, and other dependencies like OpenDKIM, UFW, and Certbot.

User Input Validation: 
Ensures the hostname and other provided information are valid before proceeding with the configuration.

Configuration File Backup:

Automatically backs up critical configuration files before making any changes.
Automatic DKIM Record Generation: 

Generates a DKIM public key and includes it in the final configuration report for DNS setup.

SMTP Configuration File Creation: 

At the end of the script execution, generates a file containing all necessary SMTP information for easy setup.
Supports Ports 587 and 465: Configures Postfix to use ports 587 (STARTTLS) and 465 (SSL) for secure email sending.

Verbose Mode:

Option to display detailed information about each step the script takes.
Command-Line Options: Allows pre-specification of options like hostname, external domain management, and verbosity for a more automated operation.


Prerequisites

Before starting, ensure you have:

A Linux server: 

Compatible with Ubuntu, Debian, CentOS, and Red Hat.
Root access or sudo privileges on the server.
A domain name that you can configure to send emails (e.g., your-domain.com).


Installation

Step 1: D

ownload the Script
Download the setup_postfix_complete.py script to your server.

bash

wget <link-to-script> -O setup_postfix_complete.py
Step 2: Grant Execution Rights
Ensure the script is executable:

bash

chmod +x setup_postfix_complete.py
Step 3: Run the Script
To launch the script, use the following command:

bash

sudo python3 setup_postfix_complete.py
Command-Line Options
You can pass options when running the script to automate some inputs:

--hostname: Specify the mail server hostname. Example:

bash

sudo python3 setup_postfix_complete.py --hostname mail.your-domain.com
--external-domain: Indicate if the domain is managed by an external provider (yes or no). Example:

bash

sudo python3 setup_postfix_complete.py --external-domain yes
--verbose: Enable verbose mode to see more details on each step:

bash

sudo python3 setup_postfix_complete.py --verbose
Monitoring the Configuration
The script generates a real-time log file. You can monitor the script's execution here: /tmp/postfix_setup_log.txt.

Final Report
Once the configuration is complete, the script generates two important files:

Configuration Report: Contains essential information, including the necessary DNS records for SPF, DKIM, and DMARC. This report is saved here: /tmp/postfix_setup_report.txt.

SMTP Information File: Contains all necessary SMTP details, such as hostname, domain, IP address, and relayhost credentials (if used). This file is saved here: /tmp/smtp_info.txt.

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
