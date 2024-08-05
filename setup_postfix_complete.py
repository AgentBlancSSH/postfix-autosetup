import os
import subprocess
import sys
import logging
import re

# Configuration des logs
logging.basicConfig(filename='/var/log/postfix_setup.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Fonction utilitaire pour exécuter une commande système
def execute_command(command, error_message):
    try:
        logging.info(f"Executing command: {command}")
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError:
        logging.error(error_message)
        sys.exit(f"\033[91m{error_message}\033[0m")

# Fonction pour installer un paquet
def install_package(package_name):
    execute_command(f"apt-get install -y {package_name}", f"Failed to install {package_name}")

# Fonction pour installer plusieurs paquets
def install_packages(packages):
    for package in packages:
        install_package(package)

# Fonction pour valider le nom d'hôte
def validate_hostname(hostname):
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$"
    if not re.match(pattern, hostname):
        sys.exit(f"\033[91mInvalid hostname: {hostname}\033[0m")

# Fonction pour valider l'adresse email
def validate_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, email):
        sys.exit(f"\033[91mInvalid email address: {email}\033[0m")

# Fonction pour vérifier et installer les prérequis
def check_and_install_prerequisites():
    logging.info("Checking and installing prerequisites...")
    prerequisites = ["postfix", "postfix-policyd-spf-python", "opendkim", "opendkim-tools", "mailutils"]
    install_packages(prerequisites)

# Configuration TLS pour Postfix
def configure_postfix_tls():
    tls_settings = {
        'smtpd_tls_cert_file': '/etc/ssl/certs/ssl-cert-snakeoil.pem',
        'smtpd_tls_key_file': '/etc/ssl/private/ssl-cert-snakeoil.key',
        'smtpd_use_tls': 'yes',
        'smtpd_tls_auth_only': 'yes',
        'smtp_tls_security_level': 'may',
        'smtpd_tls_received_header': 'yes',
        'smtp_tls_note_starttls_offer': 'yes',
        'smtpd_tls_session_cache_database': 'btree:${data_directory}/smtpd_scache',
        'smtp_tls_session_cache_database': 'btree:${data_directory}/smtp_scache',
        'tls_random_source': 'dev:/dev/urandom',
        'smtpd_tls_loglevel': '1',
    }
    for key, value in tls_settings.items():
        execute_command(f"postconf -e '{key} = {value}'", f"Failed to set {key}.")

# Configuration des restrictions Postfix
def configure_postfix_restrictions():
    restrictions = {
        'smtpd_relay_restrictions': 'permit_mynetworks permit_sasl_authenticated defer_unauth_destination',
        'smtpd_recipient_restrictions': 'permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination',
    }
    for key, value in restrictions.items():
        execute_command(f"postconf -e '{key} = {value}'", f"Failed to set {key}.")

# Configuration générale de Postfix
def configure_postfix_general(hostname, email):
    general_settings = {
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
    for key, value in general_settings.items():
        execute_command(f"postconf -e '{key} = {value}'", f"Failed to set {key}.")

# Configuration complète de Postfix
def configure_postfix(hostname, email):
    logging.info("Configuring Postfix...")
    validate_hostname(hostname)
    validate_email(email)
    configure_postfix_general(hostname, email)
    configure_postfix_tls()
    configure_postfix_restrictions()

# Configuration de DKIM pour signer les emails
def configure_dkim(domain_name):
    logging.info("Configuring DKIM...")
    execute_command("mkdir -p /etc/opendkim/keys", "Failed to create DKIM keys directory.")
    execute_command(f"opendkim-genkey -s mail -d {domain_name}", "Failed to generate DKIM keys.")
    execute_command(f"mv mail.private /etc/opendkim/keys/{domain_name}.private", "Failed to move private key.")
    execute_command(f"mv mail.txt /etc/opendkim/keys/{domain_name}.txt", "Failed to move DKIM record.")
    execute_command(f"chown opendkim:opendkim /etc/opendkim/keys/{domain_name}.private", "Failed to set permissions on private key.")
    
    with open('/etc/opendkim/KeyTable', 'a') as key_table:
        key_table.write(f"mail._domainkey.{domain_name} {domain_name}:mail:/etc/opendkim/keys/{domain_name}.private\n")
        
    with open('/etc/opendkim/SigningTable', 'a') as signing_table:
        signing_table.write(f"*@{domain_name} mail._domainkey.{domain_name}\n")
    
    with open('/etc/opendkim/TrustedHosts', 'a') as trusted_hosts:
        trusted_hosts.write(f"127.0.0.1\nlocalhost\n{domain_name}\n")

    execute_command("systemctl restart opendkim", "Failed to restart OpenDKIM.")

# Finalisation de la configuration SMTP
def finalize_smtp_configuration():
    logging.info("Finalizing SMTP configuration...")
    execute_command("systemctl restart postfix", "Failed to restart Postfix.")
    execute_command("systemctl enable postfix", "Failed to enable Postfix on boot.")
    execute_command("systemctl enable opendkim", "Failed to enable OpenDKIM on boot.")

# Sauvegarde des informations SMTP
def save_smtp_info(domain_name, email):
    logging.info("Saving SMTP information...")
    with open('/etc/postfix/smtp_info.txt', 'w') as smtp_info:
        smtp_info.write(f"SMTP Server: {domain_name}\n")
        smtp_info.write(f"Email Address: {email}\n")
        smtp_info.write("Ports: 587 (Submission), 465 (SMTPS)\n")

# Fonction principale
def main():
    print("\033[94m=== Postfix Setup Script ===\033[0m")
    hostname = input("Enter the hostname (e.g., mail.example.com): ")
    email = input("Enter the email address to use: ")
    domain_name = hostname.split(".")[-2] + "." + hostname.split(".")[-1]
    
    check_and_install_prerequisites()
    configure_postfix(hostname, email)
    configure_dkim(domain_name)
    finalize_smtp_configuration()
    save_smtp_info(domain_name, email)
    
    print("\033[92mPostfix and DKIM have been successfully configured.\033[0m")
    print(f"\033[93mAll details have been saved in /etc/postfix/smtp_info.txt\033[0m")

# Signature ASCII avec "Agent Blanc"
def signature():
    print(r"""
          
          
          _____                    _____                    _____                    _____                _____                            _____                    _____            _____                    _____                    _____          
         /\    \                  /\    \                  /\    \                  /\    \              /\    \                          /\    \                  /\    \          /\    \                  /\    \                  /\    \         
        /::\    \                /::\    \                /::\    \                /::\____\            /::\    \                        /::\    \                /::\____\        /::\    \                /::\____\                /::\    \        
       /::::\    \              /::::\    \              /::::\    \              /::::|   |            \:::\    \                      /::::\    \              /:::/    /       /::::\    \              /::::|   |               /::::\    \       
      /::::::\    \            /::::::\    \            /::::::\    \            /:::::|   |             \:::\    \                    /::::::\    \            /:::/    /       /::::::\    \            /:::::|   |              /::::::\    \      
     /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \          /::::::|   |              \:::\    \                  /:::/\:::\    \          /:::/    /       /:::/\:::\    \          /::::::|   |             /:::/\:::\    \     
    /:::/__\:::\    \        /:::/  \:::\    \        /:::/__\:::\    \        /:::/|::|   |               \:::\    \                /:::/__\:::\    \        /:::/    /       /:::/__\:::\    \        /:::/|::|   |            /:::/  \:::\    \    
   /::::\   \:::\    \      /:::/    \:::\    \      /::::\   \:::\    \      /:::/ |::|   |               /::::\    \              /::::\   \:::\    \      /:::/    /       /::::\   \:::\    \      /:::/ |::|   |           /:::/    \:::\    \   
  /::::::\   \:::\    \    /:::/    / \:::\    \    /::::::\   \:::\    \    /:::/  |::|   | _____        /::::::\    \            /::::::\   \:::\    \    /:::/    /       /::::::\   \:::\    \    /:::/  |::|   | _____    /:::/    / \:::\    \  
 /:::/\:::\   \:::\    \  /:::/    /   \:::\ ___\  /:::/\:::\   \:::\    \  /:::/   |::|   |/\    \      /:::/\:::\    \          /:::/\:::\   \:::\ ___\  /:::/    /       /:::/\:::\   \:::\    \  /:::/   |::|   |/\    \  /:::/    /   \:::\    \ 
/:::/  \:::\   \:::\____\/:::/____/  ___\:::|    |/:::/__\:::\   \:::\____\/:: /    |::|   /::\____\    /:::/  \:::\____\        /:::/__\:::\   \:::|    |/:::/____/       /:::/  \:::\   \:::\____\/:: /    |::|   /::\____\/:::/____/     \:::\____\
\::/    \:::\  /:::/    /\:::\    \ /\  /:::|____|\:::\   \:::\   \::/    /\::/    /|::|  /:::/    /   /:::/    \::/    /        \:::\   \:::\  /:::|____|\:::\    \       \::/    \:::\  /:::/    /\::/    /|::|  /:::/    /\:::\    \      \::/    /
 \/____/ \:::\/:::/    /  \:::\    /::\ \::/    /  \:::\   \:::\   \/____/  \/____/ |::| /:::/    /   /:::/    / \/____/          \:::\   \:::\/:::/    /  \:::\    \       \/____/ \:::\/:::/    /  \/____/ |::| /:::/    /  \:::\    \      \/____/ 
          \::::::/    /    \:::\   \:::\ \/____/    \:::\   \:::\    \              |::|/:::/    /   /:::/    /                    \:::\   \::::::/    /    \:::\    \               \::::::/    /           |::|/:::/    /    \:::\    \             
           \::::/    /      \:::\   \:::\____\       \:::\   \:::\____\             |::::::/    /   /:::/    /                      \:::\   \::::/    /      \:::\    \               \::::/    /            |::::::/    /      \:::\    \            
           /:::/    /        \:::\  /:::/    /        \:::\   \::/    /             |:::::/    /    \::/    /                        \:::\  /:::/    /        \:::\    \               /:::/    /             |:::::/    /        \:::\    \           
          /:::/    /          \:::\/:::/    /          \:::\   \/____/              |::::/    /      \/____/                          \:::\/:::/    /          \:::\    \             /:::/    /              |::::/    /          \:::\    \          
         /:::/    /            \::::::/    /            \:::\    \                  /:::/    /                                         \::::::/    /            \:::\    \           /:::/    /               /:::/    /            \:::\    \         
        /:::/    /              \::::/    /              \:::\____\                /:::/    /                                           \::::/    /              \:::\____\        /:::/    /               /:::/    /              \:::\____\        
        \::/    /                \::/____/                \::/    /                \::/    /                                             \::/____/                \::/    /        \::/    /                \::/    /                \::/    /        
         \/____/                                           \/____/                  \/____/                                               ~~                       \/____/          \/____/                  \/____/                  \/____/         
                                                                                                                                                                                                                                                      
                                                
     """)
    print("Agent Blanc")

if __name__ == "__main__":
    main()
    signature()
