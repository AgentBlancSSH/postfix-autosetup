import os
import subprocess
import sys
import shutil
import socket
import argparse

# Couleurs pour les sorties
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"

def print_colored(message, color):
    print(f"{color}{message}{RESET}")

def run_command(command, log_file_path=None, verbose=False):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if verbose:
            print(result.stdout)
        if result.returncode != 0:
            error_message = f"Erreur lors de l'exécution de la commande {command}: {result.stderr}"
            print_colored(error_message, RED)
            if log_file_path:
                with open(log_file_path, "a") as log_file:
                    log_file.write(error_message + "\n")
            sys.exit(1)
        return result.stdout
    except Exception as e:
        error_message = f"Une erreur s'est produite: {str(e)}"
        print_colored(error_message, RED)
        if log_file_path:
            with open(log_file_path, "a") as log_file:
                log_file.write(error_message + "\n")
        sys.exit(1)

def update_log_page(message, log_file_path):
    with open(log_file_path, "a") as log_file:
        log_file.write(message + "\n")
    print_colored(message, GREEN)

def check_dns_resolution(domain, log_file_path):
    try:
        ip = socket.gethostbyname(domain)
        update_log_page(f"Résolution DNS pour {domain} : {ip}", log_file_path)
        return True
    except socket.gaierror:
        update_log_page(f"Échec de la résolution DNS pour {domain}.", log_file_path)
        return False

def update_certbot(log_file_path):
    update_log_page("Mise à jour de certbot...", log_file_path)
    run_command("sudo apt-get update", log_file_path)
    run_command("sudo apt-get install --only-upgrade certbot", log_file_path)

def generate_ssl_certificates(domain, email, log_file_path, verbose=False):
    update_log_page(f"Vérification de la résolution DNS pour {domain}...", log_file_path)
    if not check_dns_resolution(domain, log_file_path):
        handle_error(f"Échec de la résolution DNS pour {domain}.", log_file_path)

    # Mise à jour de certbot
    update_certbot(log_file_path)

    # Stop Nginx temporarily
    run_command("sudo systemctl stop nginx", log_file_path, verbose)

    # Use certbot to generate SSL certificates
    cert_command = f"sudo certbot certonly --standalone -d {domain} --agree-tos -m {email} --non-interactive --verbose"
    try:
        run_command(cert_command, log_file_path, verbose)
        update_log_page(f"Certificats SSL générés pour {domain} avec certbot.", log_file_path)
    except subprocess.CalledProcessError as e:
        certbot_log = check_certbot_log()
        handle_error(f"Échec de la génération des certificats SSL pour {domain}. Détails du log:\n{certbot_log}", log_file_path)

    # Start Nginx again
    run_command("sudo systemctl start nginx", log_file_path, verbose)

def check_certbot_log():
    log_path = "/var/log/letsencrypt/letsencrypt.log"
    if os.path.exists(log_path):
        with open(log_path, "r") as log_file:
            return log_file.read()
    else:
        return "Le fichier de log certbot n'a pas été trouvé."

def setup_postfix(hostname, domain, log_file_path, verbose=False):
    update_log_page(f"Configuration de Postfix pour {hostname} et {domain}...", log_file_path)
    postfix_main_cf = "/etc/postfix/main.cf"
    master_cf = "/etc/postfix/master.cf"

    # Configuration minimale de Postfix
    if not os.path.exists(postfix_main_cf):
        with open(postfix_main_cf, 'w') as postfix_config:
            postfix_config.write("# Configuration Postfix minimale\n")
            postfix_config.write(f"myhostname = {hostname}\n")
            postfix_config.write(f"mydomain = {domain}\n")
            postfix_config.write("myorigin = $mydomain\n")
            postfix_config.write("inet_interfaces = all\n")
            postfix_config.write("inet_protocols = ipv4\n")
            postfix_config.write("smtpd_use_tls=yes\n")
            postfix_config.write("smtpd_tls_auth_only = yes\n")
            postfix_config.write(f"mydestination = {hostname}, localhost.$mydomain, localhost\n")
            postfix_config.write("relayhost = \n")
            postfix_config.write("mynetworks = 127.0.0.0/8 [::1]/128\n")
            postfix_config.write("mailbox_size_limit = 0\n")
            postfix_config.write("recipient_delimiter = +\n")
            postfix_config.write("smtpd_sasl_auth_enable = yes\n")
            postfix_config.write("smtpd_sasl_security_options = noanonymous\n")
            postfix_config.write("smtpd_sasl_local_domain = $myhostname\n")
            postfix_config.write("smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination\n")
        update_log_page(f"Configuration Postfix minimale écrite dans {postfix_main_cf}", log_file_path)
    else:
        update_log_page(f"Le fichier de configuration {postfix_main_cf} existe déjà.", log_file_path)

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

    # Redémarrage de Postfix
    run_command("sudo systemctl restart postfix", log_file_path, verbose)
    update_log_page("Postfix redémarré avec succès.", log_file_path)

def check_smtp_ports(log_file_path):
    update_log_page("Vérification des ports SMTP...", log_file_path)

    # Test sur le port 587
    result_587 = subprocess.run("openssl s_client -starttls smtp -connect localhost:587 -crlf -ign_eof", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if "250" in result_587.stdout:
        update_log_page("Le serveur SMTP est opérationnel sur le port 587 avec TLS.", log_file_path)
    else:
        update_log_page("Échec de la connexion TLS au serveur SMTP sur le port 587.", log_file_path)

    # Test sur le port 465
    result_465 = subprocess.run("openssl s_client -connect localhost:465 -ssl3 -crlf -ign_eof", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if "250" in result_465.stdout:
        update_log_page("Le serveur SMTP est opérationnel sur le port 465 avec SSL.", log_file_path)
    else:
        update_log_page("Échec de la connexion SSL au serveur SMTP sur le port 465.", log_file_path)

def setup_firewall(log_file_path):
    update_log_page("Configuration du pare-feu UFW...", log_file_path)
    run_command("sudo ufw allow OpenSSH", log_file_path)
    run_command("sudo ufw allow 'Nginx Full'", log_file_path)
    run_command("sudo ufw allow 587/tcp", log_file_path)
    run_command("sudo ufw allow 465/tcp", log_file_path)
    run_command("sudo ufw --force enable", log_file_path)
    update_log_page("Pare-feu UFW configuré avec succès.", log_file_path)

def setup_dkim(domain, log_file_path, verbose=False):
    dkim_dir = f"/etc/opendkim/keys/{domain}"
    os.makedirs(dkim_dir, exist_ok=True)
    update_log_page(f"Répertoire DKIM créé : {dkim_dir}", log_file_path)

    dkim_key_path = os.path.join(dkim_dir, "default")
    dkim_txt_record_path = os.path.join(dkim_dir, "default.txt")

    # Génération de la clé DKIM
    run_command(f"opendkim-genkey -s default -d {domain}", log_file_path, verbose)

    # Déplacement des fichiers générés vers le répertoire approprié
    run_command(f"mv default.private {dkim_key_path}", log_file_path, verbose)
    run_command(f"mv default.txt {dkim_txt_record_path}", log_file_path, verbose)

    update_log_page(f"Clé DKIM générée et enregistrée dans {dkim_key_path}", log_file_path)

def main():
    parser = argparse.ArgumentParser(description="Script de configuration complète de Postfix et Let's Encrypt.")
    parser.add_argument("-d", "--domain", help="Le nom de domaine pour lequel configurer Let's Encrypt", required=True)
    parser.add_argument("-e", "--email", help="Adresse email pour Let's Encrypt", required=True)
    parser.add_argument("-v", "--verbose", help="Activer le mode verbeux", action="store_true")
    parser.add_argument("-l", "--log", help="Fichier de log", default="/var/log/setup_postfix_complete.log")
    args = parser.parse_args()

    log_file_path = args.log

    if os.geteuid() != 0:
        print_colored("Ce script doit être exécuté avec les privilèges root.", RED)
        sys.exit(1)

    hostname = args.domain
    domain = ".".join(hostname.split(".")[1:])

    # Vérifiez si Nginx est installé
    if shutil.which("nginx") is None:
        print_colored("Le paquet nginx n'est pas installé. Installation en cours...", YELLOW)
        run_command("sudo apt-get install -y nginx", log_file_path, args.verbose)

    setup_firewall(log_file_path)
    setup_postfix(hostname, domain, log_file_path, args.verbose)
    setup_dkim(domain, log_file_path, args.verbose)
    generate_ssl_certificates(domain, args.email, log_file_path, args.verbose)
    check_smtp_ports(log_file_path)

if __name__ == "__main__":
    main()
