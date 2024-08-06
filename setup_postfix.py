import os
import subprocess
import sys
import logging
import re
import smtplib
from email.mime.text import MIMEText

# Configuration des logs
logging.basicConfig(filename='/var/log/postfix_setup.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Couleurs pour le terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
ENDC = "\033[0m"

# Fonction utilitaire pour exécuter une commande système
def execute_command(command, error_message):
    try:
        logging.debug(f"Executing command: {command}")
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"{error_message}: {e}")
        sys.exit(f"{RED}{error_message}{ENDC}")

# Vérification de l'installation de Postfix
def check_postfix_installation():
    logging.info("Checking if Postfix is installed...")
    if not os.path.isfile('/usr/sbin/postfix'):
        sys.exit(f"{RED}Postfix is not installed. Please install Postfix before running this script.{ENDC}")
    
    if not os.path.isfile('/etc/postfix/main.cf'):
        logging.info("Postfix main configuration file not found, creating a default one...")
        execute_command("postconf -d > /etc/postfix/main.cf", "Failed to create default main.cf")

# Validation du nom d'hôte
def validate_hostname(hostname):
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    if not re.match(pattern, hostname):
        sys.exit(f"{RED}Invalid hostname: {hostname}{ENDC}")

# Validation de l'adresse email
def validate_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, email):
        sys.exit(f"{RED}Invalid email address: {email}{ENDC}")

# Configuration générale de Postfix
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

# Configuration des ports SMTP dans master.cf
def configure_postfix_ports():
    logging.info("Configuring Postfix SMTP ports...")
    master_cf_path = "/etc/postfix/master.cf"

    ports_config = """
submission inet n       -       y       -       -       smtpd
  -o smtpd_tls_security_level=may
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       y       -       -       smtpd
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
"""
    
    try:
        with open(master_cf_path, "a") as master_cf:
            master_cf.write(ports_config)
        logging.info("Successfully configured Postfix SMTP ports in master.cf.")
    except Exception as e:
        logging.error(f"Failed to configure Postfix SMTP ports: {e}")
        sys.exit(f"{RED}Failed to configure Postfix SMTP ports{ENDC}")

# Configuration de DKIM
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

# Finalisation de la configuration
def finalize_smtp_configuration():
    logging.info("Finalizing SMTP configuration...")
    execute_command("systemctl restart postfix", "Failed to restart Postfix")
    execute_command("systemctl enable postfix", "Failed to enable Postfix on boot")
    execute_command("systemctl enable opendkim", "Failed to enable OpenDKIM on boot")

# Sauvegarde des informations SMTP
def save_smtp_info(domain_name, email):
    logging.info("Saving SMTP information...")
    with open('/etc/postfix/smtp_info.txt', 'w') as smtp_info:
        smtp_info.write(f"SMTP Server: {domain_name}\n")
        smtp_info.write(f"Email Address: {email}\n")
        smtp_info.write("Ports: 587 (Submission), 465 (SMTPS)\n")

# Fonction pour envoyer un e-mail de test
def send_test_email(smtp_server, smtp_port, email_sender, email_recipient):
    logging.info("Sending a test email...")
    subject = "Test Email from Postfix Setup Script"
    body = "This is a test email sent to confirm that Postfix SMTP is working correctly."
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = email_sender
    msg['To'] = email_recipient

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.sendmail(email_sender, [email_recipient], msg.as_string())
            logging.info("Test email sent successfully.")
            print(f"{GREEN}Test email sent successfully.{ENDC}")
    except Exception as e:
        logging.error(f"Failed to send test email: {e}")
        sys.exit(f"{RED}Failed to send test email: {e}{ENDC}")

# Fonction principale
def main():
    print(f"{BLUE}=== Postfix Setup Script ==={ENDC}")
    hostname = input(f"{YELLOW}Enter the hostname (e.g., mail.example.com): {ENDC}")
    email = input(f"{YELLOW}Enter the email address to use: {ENDC}")
    domain_name = '.'.join(hostname.split('.')[-2:])
    test_email = input(f"{YELLOW}Enter the recipient email address for the test (e.g., your-email@example.com): {ENDC}")
    
    check_postfix_installation()
    validate_hostname(hostname)
    validate_email(email)
    validate_email(test_email)

    configure_postfix_general(hostname, email)
    configure_postfix_ports()
    configure_dkim(domain_name)
    finalize_smtp_configuration()
    save_smtp_info(domain_name, email)
    
    # Envoi du mail de test
    send_test_email(hostname, 587, email, test_email)

    print(f"{GREEN}Postfix and DKIM have been successfully configured.{ENDC}")
    print(f"{YELLOW}All details have been saved in /etc/postfix/smtp_info.txt{ENDC}")

if __name__ == "__main__":
    main()
