import os
import subprocess
import sys
import logging
import re

# Configuration des logs
logging.basicConfig(filename='/var/log/postfix_setup.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def execute_command(command, error_message):
    try:
        logging.debug(f"Executing command: {command}")
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"{error_message}: {e}")
        sys.exit(f"\033[91m{error_message}\033[0m")

def validate_hostname(hostname):
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    if not re.match(pattern, hostname):
        sys.exit(f"\033[91mInvalid hostname: {hostname}\033[0m")

def validate_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, email):
        sys.exit(f"\033[91mInvalid email address: {email}\033[0m")

def configure_postfix_general(hostname, email):
    logging.info("Configuring Postfix general settings...")
    settings = {
        'myhostname': hostname,
        'myorigin': email,
        'mydestination': 'localhost',
        'inet_interfaces': 'all',
        'inet_protocols': 'ipv4',
        'home_mailbox': 'Maildir/',
        'smtpd_sasl_type': 'dovecot',
        'smtpd_sasl_path': 'private/auth',
        'smtpd_sasl_auth_enable': 'yes',
        'broken_sasl_auth_clients': 'yes'
    }
    for key, value in settings.items():
        execute_command(f"postconf -e '{key} = {value}'", f"Failed to set {key}")

def configure_postfix_ports():
    logging.info("Configuring Postfix SMTP ports...")
    settings = {
        'smtpd_tls_security_level': 'may',
        'submission inet n       -       y       -       -       smtpd': '',
        'smtps     inet  n       -       y       -       -       smtpd': '',
        '  -o smtpd_tls_wrappermode=yes': '',
        '  -o smtpd_sasl_auth_enable=yes': '',
        '  -o smtpd_reject_unlisted_recipient=yes': '',
        '  -o smtpd_client_restrictions=permit_sasl_authenticated,reject': '',
        '  -o milter_macro_daemon_name=ORIGINATING': ''
    }
    for key, value in settings.items():
        execute_command(f"postconf -Me '{key}'", f"Failed to set {key}")

def configure_dkim(domain_name):
    logging.info("Configuring DKIM...")
    execute_command("mkdir -p /etc/opendkim/keys", "Failed to create DKIM keys directory")
    execute_command(f"opendkim-genkey -s mail -d {domain_name}", "Failed to generate DKIM keys")
    execute_command(f"mv mail.private /etc/opendkim/keys/{domain_name}.private", "Failed to move private key")
    execute_command(f"mv mail.txt /etc/opendkim/keys/{domain_name}.txt", "Failed to move DKIM record")
    execute_command(f"chown opendkim:opendkim /etc/opendkim/keys/{domain_name}.private", "Failed to set permissions on private key")

    with open('/etc/opendkim/KeyTable', 'a') as key_table:
        key_table.write(f"mail._domainkey.{domain_name} {domain_name}:mail:/etc/opendkim/keys/{domain_name}.private\n")
        
    with open('/etc/opendkim/SigningTable', 'a') as signing_table:
        signing_table.write(f"*@{domain_name} mail._domainkey.{domain_name}\n")
    
    with open('/etc/opendkim/TrustedHosts', 'a') as trusted_hosts:
        trusted_hosts.write(f"127.0.0.1\nlocalhost\n{domain_name}\n")

    execute_command("systemctl restart opendkim", "Failed to restart OpenDKIM")

def finalize_smtp_configuration():
    logging.info("Finalizing SMTP configuration...")
    execute_command("systemctl restart postfix", "Failed to restart Postfix")
    execute_command("systemctl enable postfix", "Failed to enable Postfix on boot")
    execute_command("systemctl enable opendkim", "Failed to enable OpenDKIM on boot")

def save_smtp_info(domain_name, email):
    logging.info("Saving SMTP information...")
    with open('/etc/postfix/smtp_info.txt', 'w') as smtp_info:
        smtp_info.write(f"SMTP Server: {domain_name}\n")
        smtp_info.write(f"Email Address: {email}\n")
        smtp_info.write("Ports: 587 (Submission), 465 (SMTPS)\n")

def main():
    print("\033[94m=== Postfix Setup Script ===\033[0m")
    hostname = input("Enter the hostname (e.g., mail.example.com): ")
    email = input("Enter the email address to use: ")
    domain_name = '.'.join(hostname.split('.')[-2:])
    
    validate_hostname(hostname)
    validate_email(email)

    configure_postfix_general(hostname, email)
    configure_postfix_ports()
    configure_dkim(domain_name)
    finalize_smtp_configuration()
    save_smtp_info(domain_name, email)
    
    print("\033[92mPostfix and DKIM have been successfully configured.\033[0m")
    print(f"\033[93mAll details have been saved in /etc/postfix/smtp_info.txt\033[0m")

if __name__ == "__main__":
    main()
