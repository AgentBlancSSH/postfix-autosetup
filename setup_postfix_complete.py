import os
import subprocess
import sys
import argparse
import shutil
import smtplib
from email.mime.text import MIMEText

# Couleurs pour les sorties
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"

def print_colored(message, color):
    print(f"{color}{message}{RESET}")

def handle_error(message, log_file_path):
    with open(log_file_path, 'a') as log_file:
        log_file.write(message + "\n")
    print_colored(message, RED)
    sys.exit(1)

def run_command(command, log_file_path, verbose=False):
    try:
        with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            with open(log_file_path, 'a') as log_file:
                for line in process.stdout:
                    log_file.write(line)
                    if verbose:
                        print(line, end='')
                for error in process.stderr:
                    log_file.write(error)
                    if verbose:
                        print(f"Erreur : {error}", end='')
            process.wait()
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command)
    except Exception as e:
        handle_error(f"Une erreur s'est produite lors de l'exécution de la commande {command}: {str(e)}", log_file_path)

def create_log_page(log_file_path):
    try:
        with open(log_file_path, 'w') as log_file:
            log_file.write("Initialisation du script de configuration du serveur Postfix...\n")
    except IOError as e:
        print_colored(f"Erreur lors de la création du fichier log: {str(e)}", RED)
        sys.exit(1)

def update_log_page(message, log_file_path):
    with open(log_file_path, 'a') as log_file:
        log_file.write(message + "\n")
    print_colored(message, BLUE)

def check_certbot_log():
    log_path = "/var/log/letsencrypt/letsencrypt.log"
    if os.path.exists(log_path):
        with open(log_path, 'r') as log_file:
            return log_file.read()
    else:
        return "Aucun log certbot trouvé."

def check_dns_resolution(domain, log_file_path):
    try:
        command = f"dig +short {domain}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ip_addresses = result.stdout.strip()
        if ip_addresses:
            update_log_page(f"Résolution DNS pour {domain} : {ip_addresses}", log_file_path)
            return True
        else:
            handle_error(f"Échec de la résolution DNS pour {domain}.", log_file_path)
    except Exception as e:
        handle_error(f"Une erreur s'est produite lors de la résolution DNS pour {domain}: {str(e)}", log_file_path)

def update_certbot(log_file_path):
    try:
        update_log_page("Mise à jour de certbot...", log_file_path)
        run_command("sudo apt-get update && sudo apt-get install --only-upgrade certbot", log_file_path, verbose=True)
    except Exception as e:
        handle_error(f"Une erreur s'est produite lors de la mise à jour de certbot: {str(e)}", log_file_path)

def generate_dkim_key(domain, log_file_path, verbose=False):
    dkim_dir = f"/etc/opendkim/keys/{domain}"
    if not os.path.exists(dkim_dir):
        os.makedirs(dkim_dir)

    # Générer la clé DKIM
    command = f"opendkim-genkey -s default -d {domain} -D {dkim_dir}"
    run_command(command, log_file_path, verbose)

    # Définir les permissions
    run_command(f"chown opendkim:opendkim {dkim_dir}/default.private", log_file_path, verbose)
    run_command(f"chmod 600 {dkim_dir}/default.private", log_file_path, verbose)

    # Retourner le contenu du fichier de clé publique
    with open(f"{dkim_dir}/default.txt", 'r') as f:
        dkim_record = f.read().replace("\n", "")
    
    return dkim_record

def generate_report(report_file_path, hostname, domain, ip_address, dkim_record):
    with open(report_file_path, 'w') as report_file:
        report_file.write(f"Rapport de configuration du serveur Postfix\n")
        report_file.write(f"=============================================\n")
        report_file.write(f"Nom d'hôte : {hostname}\n")
        report_file.write(f"Domaine : {domain}\n")
        report_file.write(f"Adresse IP : {ip_address}\n")
        
        report_file.write(f"\nConfigurations DNS recommandées :\n")
        report_file.write(f"- SPF : v=spf1 a mx ip4:{ip_address} ~all\n")
        report_file.write(f"- DKIM : default._domainkey.{domain} IN TXT ( \"{dkim_record}\" )\n")
        report_file.write(f"- DMARC : _dmarc.{domain} IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}\"")

def backup_file(file_path):
    try:
        backup_path = file_path + ".bak"
        shutil.copy(file_path, backup_path)
        print_colored(f"Sauvegarde du fichier {file_path} vers {backup_path}", GREEN)
    except IOError as e:
        print_colored(f"Erreur lors de la sauvegarde du fichier: {str(e)}", RED)
        sys.exit(1)

def check_prerequisites(log_file_path):
    required_packages = ["postfix", "mailutils", "libsasl2-modules", "opendkim", "certbot", "ufw"]
    for package in required_packages:
        try:
            result = subprocess.run(['dpkg', '-l', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                update_log_page(f"Le paquet {package} n'est pas installé. Installation en cours...", log_file_path)
                run_command(f"sudo apt-get install {package} -y", log_file_path)
            else:
                update_log_page(f"Le paquet {package} est déjà installé.", log_file_path)
        except subprocess.CalledProcessError as e:
            handle_error(f"Erreur lors de la vérification des prérequis: {str(e)}", log_file_path)

def detect_os():
    with open("/etc/os-release") as f:
        os_info = f.read().lower()
        if "ubuntu" in os_info or "debian" in os_info:
            return "debian"
        elif "centos" in os_info or "rhel" in os_info:
            return "rhel"
        else:
            return "unknown"

def validate_hostname(hostname):
    import re
    if re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        return True
    return False

def generate_smtp_info_file(smtp_info_file_path, hostname, domain, ip_address, dkim_record):
    with open(smtp_info_file_path, 'w') as smtp_info_file:
        smtp_info_file.write(f"Informations SMTP pour le serveur {hostname}\n")
        smtp_info_file.write(f"=============================================\n")
        smtp_info_file.write(f"Nom d'hôte : {hostname}\n")
        smtp_info_file.write(f"Domaine : {domain}\n")
        smtp_info_file.write(f"Adresse IP : {ip_address}\n")
        smtp_info_file.write("\nConfiguration SMTP :\n")
        smtp_info_file.write(f"- SMTP Server : {hostname}\n")
        smtp_info_file.write(f"- Port : 587\n")
        smtp_info_file.write(f"- TLS : Oui\n")
        smtp_info_file.write(f"- SSL : Port 465 activé\n")
        
        smtp_info_file.write("- Utilisation directe sans relayhost.\n")
        
        smtp_info_file.write("\nParamètres supplémentaires :\n")
        smtp_info_file.write(f"- SPF : v=spf1 a mx ip4:{ip_address} ~all\n")
        smtp_info_file.write(f"- DKIM : default._domainkey.{domain} IN TXT ( \"{dkim_record}\" )\n")
        smtp_info_file.write(f"- DMARC : _dmarc.{domain} IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}\"")

def configure_postfix(hostname, domain, ip_address, log_file_path, verbose):
    postfix_main_cf = "/etc/postfix/main.cf"
    master_cf = "/etc/postfix/master.cf"
    
    # Check if the main.cf file exists
    if not os.path.exists(postfix_main_cf):
        # Create a minimal main.cf if it doesn't exist
        with open(postfix_main_cf, 'w') as postfix_config:
            postfix_config.write("# Configuration Postfix minimale\n")
            postfix_config.write(f"myhostname = {hostname}\n")
            postfix_config.write(f"mydomain = {domain}\n")
            postfix_config.write("myorigin = $mydomain\n")
            postfix_config.write("inet_interfaces = all\n")
            postfix_config.write("inet_protocols = ipv4\n")
            postfix_config.write("smtpd_use_tls=yes\n")
            postfix_config.write("smtpd_tls_auth_only = yes\n")
            postfix_config.write(f"mydestination = {hostname}, localhost.{domain}, localhost\n")
            postfix_config.write("relayhost = \n")
            postfix_config.write("mynetworks = 127.0.0.0/8 [::1]/128\n")
            postfix_config.write("mailbox_size_limit = 0\n")
            postfix_config.write("recipient_delimiter = +\n")
            postfix_config.write("smtpd_sasl_auth_enable = yes\n")
            postfix_config.write("smtpd_sasl_security_options = noanonymous\n")
            postfix_config.write("smtpd_sasl_local_domain = $myhostname\n")
            postfix_config.write("smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination\n")
        
        update_log_page(f"Fichier de configuration minimal créé à {postfix_main_cf}", log_file_path)
    
    # Sauvegarde du fichier de configuration actuel
    backup_file(postfix_main_cf)
    
    # Ajouter des configurations supplémentaires
    with open(postfix_main_cf, 'a') as postfix_config:
        postfix_config.write(f"smtpd_tls_cert_file=/etc/letsencrypt/live/{domain}/fullchain.pem\n")
        postfix_config.write(f"smtpd_tls_key_file=/etc/letsencrypt/live/{domain}/privkey.pem\n")
        postfix_config.write("smtp_tls_security_level = may\n")
        postfix_config.write("smtp_tls_note_starttls_offer = yes\n")
    
    # Configurer les ports 587 et 465 dans master.cf
    with open(master_cf, 'a') as master_config:
        master_config.write(f"\nsubmission inet n       -       y       -       -       smtpd\n")
        master_config.write(f"  -o syslog_name=postfix/submission\n")
        master_config.write(f"  -o smtpd_tls_security_level=encrypt\n")
        master_config.write(f"  -o smtpd_sasl_auth_enable=yes\n")
        master_config.write(f"  -o smtpd_client_restrictions=permit_sasl_authenticated,reject\n")
        master_config.write(f"  -o milter_macro_daemon_name=ORIGINATING\n")
        
        master_config.write(f"\nsmtps     inet  n       -       y       -       -       smtpd\n")
        master_config.write(f"  -o syslog_name=postfix/smtps\n")
        master_config.write(f"  -o smtpd_tls_wrappermode=yes\n")
        master_config.write(f"  -o smtpd_sasl_auth_enable=yes\n")
        master_config.write(f"  -o smtpd_client_restrictions=permit_sasl_authenticated,reject\n")
        master_config.write(f"  -o milter_macro_daemon_name=ORIGINATING\n")
    
    update_log_page(f"Configuration des ports 587 (TLS) et 465 (SSL) écrite dans {master_cf}", log_file_path)

    # Restart Postfix to apply the configuration
    run_command("sudo systemctl restart postfix", log_file_path, verbose)

def generate_ssl_certificates(domain, email, log_file_path, verbose=False):
    # Vérifications avant génération des certificats
    update_log_page(f"Vérification de la résolution DNS pour {domain}...", log_file_path)
    if not check_dns_resolution(domain, log_file_path):
        handle_error(f"Échec de la résolution DNS pour {domain}.", log_file_path)
    
    # Mise à jour de certbot
    update_certbot(log_file_path)

    # Utiliser certbot pour générer les certificats SSL
    cert_command = f"sudo certbot certonly --standalone -d {domain} --agree-tos -m {email} --non-interactive --verbose"
    try:
        run_command(cert_command, log_file_path, verbose)
        update_log_page(f"Certificats SSL générés pour {domain} avec certbot.", log_file_path)
    except subprocess.CalledProcessError as e:
        # Si l'exécution échoue, afficher les détails du log certbot
        certbot_log = check_certbot_log()
        handle_error(f"Échec de la génération des certificats SSL pour {domain}. Détails du log:\n{certbot_log}", log_file_path)

def check_smtp_ports(log_file_path):
    # Test sur le port 587
    result_587 = subprocess.run("openssl s_client -starttls smtp -connect localhost:587 -crlf -ign_eof", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if "250" in result_587.stdout:
        update_log_page("Le serveur SMTP est opérationnel sur le port 587 avec TLS.", log_file_path)
    else:
        handle_error("Échec de la connexion TLS au serveur SMTP sur le port 587.", log_file_path)

    # Test sur le port 465
    result_465 = subprocess.run("openssl s_client -connect localhost:465 -ssl3 -crlf -ign_eof", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if "250" in result_465.stdout:
        update_log_page("Le serveur SMTP est opérationnel sur le port 465 avec SSL.", log_file_path)
    else:
        handle_error("Échec de la connexion SSL au serveur SMTP sur le port 465.", log_file_path)

def send_test_email(hostname, log_file_path, from_addr, to_addr):
    try:
        msg = MIMEText("Ceci est un test de configuration SMTP.")
        msg['Subject'] = 'Test de configuration SMTP'
        msg['From'] = from_addr
        msg['To'] = to_addr

        with smtplib.SMTP(hostname, 587) as server:
            server.starttls()
            server.sendmail(from_addr, [to_addr], msg.as_string())
        
        update_log_page(f"Email de test envoyé avec succès de {from_addr} à {to_addr}", log_file_path)
        print_colored(f"Email de test envoyé avec succès de {from_addr} à {to_addr}", GREEN)

    except Exception as e:
        handle_error(f"Échec de l'envoi de l'email de test: {str(e)}", log_file_path)

def setup_server(args):
    log_file_path = "/tmp/postfix_setup_log.txt"
    report_file_path = "/tmp/postfix_setup_report.txt"
    smtp_info_file_path = "/tmp/smtp_info.txt"
    
    create_log_page(log_file_path)

    try:
        update_log_page("Vérification des prérequis...", log_file_path)
        check_prerequisites(log_file_path)

        os_type = detect_os()
        if os_type == "unknown":
            handle_error("Distribution Linux non reconnue. Script interrompu.", log_file_path)
        
        update_log_page(f"Distribution Linux détectée : {os_type.capitalize()}", log_file_path)

        hostname = args.hostname or input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")
        while not validate_hostname(hostname):
            print_colored("Nom d'hôte invalide. Veuillez réessayer.", RED)
            hostname = input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")

        domain = hostname.split('.', 1)[1]
        ip_address = subprocess.getoutput("hostname -I").strip()

        # Générer les certificats SSL avec Let's Encrypt
        email = input("Entrez votre adresse email pour Let's Encrypt (pour les notifications de renouvellement) : ")
        generate_ssl_certificates(domain, email, log_file_path, args.verbose)

        # Générer la clé DKIM
        dkim_record = generate_dkim_key(domain, log_file_path, args.verbose)

        # Configuration Postfix
        configure_postfix(hostname, domain, ip_address, log_file_path, args.verbose)
        
        # Vérifier les ports SMTP
        check_smtp_ports(log_file_path)
        
        # Test d'envoi d'email
        from_addr = "test@" + domain
        to_addr = input("Entrez une adresse email pour recevoir le test : ")
        send_test_email(hostname, log_file_path, from_addr, to_addr)
        
        # Générer le rapport et les infos SMTP
        generate_report(report_file_path, hostname, domain, ip_address, dkim_record)
        generate_smtp_info_file(smtp_info_file_path, hostname, domain, ip_address, dkim_record)
        
        update_log_page(f"Rapport de configuration généré à l'emplacement : {report_file_path}", log_file_path)
        update_log_page(f"Informations SMTP générées à l'emplacement : {smtp_info_file_path}", log_file_path)
    except Exception as e:
        handle_error(f"Échec de la configuration du serveur: {str(e)}", log_file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de configuration de serveur Postfix")
    parser.add_argument("--hostname", help="Nom d'hôte du serveur de messagerie")
    parser.add_argument("--verbose", action="store_true", help="Activer le mode verbeux")
    args = parser.parse_args()

    setup_server(args)
