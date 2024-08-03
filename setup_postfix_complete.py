import os
import subprocess
import sys
import time
import argparse

# Fonction pour exécuter une commande et capturer le log en temps réel
def run_command(command, log_file, verbose=False):
    try:
        with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                log_file.write(line)
                if verbose:
                    print(line, end='')
            for error in process.stderr:
                log_file.write(error)
                if verbose:
                    print(f"Erreur : {error}", end='')
    except Exception as e:
        update_log_page(f"Une erreur s'est produite lors de l'exécution de la commande {command}: {str(e)}", log_file)
        raise

def create_log_page(log_file_path):
    with open(log_file_path, 'w') as log_file:
        log_file.write("Initialisation du script de configuration du serveur Postfix...\n")

def update_log_page(message, log_file_path):
    with open(log_file_path, 'a') as log_file:
        log_file.write(message + "\n")
    print(message)

def generate_report(report_file_path, hostname, domain, ip_address, external_domain):
    dkim_record = generate_dkim_record(domain)
    with open(report_file_path, 'w') as report_file:
        report_file.write(f"Rapport de configuration du serveur Postfix\n")
        report_file.write(f"=============================================\n")
        report_file.write(f"Nom d'hôte : {hostname}\n")
        report_file.write(f"Domaine : {domain}\n")
        report_file.write(f"Adresse IP : {ip_address}\n")
        
        if external_domain == "oui":
            report_file.write(f"\nLe domaine est géré par un fournisseur externe. Voici les configurations DNS à effectuer chez votre fournisseur DNS:\n")
        else:
            report_file.write(f"\nConfigurations DNS recommandées :\n")

        report_file.write(f"- SPF : v=spf1 a mx ip4:{ip_address} ~all\n")
        report_file.write(f"- DKIM : default._domainkey.{domain} IN TXT ( \"{dkim_record}\" )\n")
        report_file.write(f"- DMARC : _dmarc.{domain} IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}\"")

def generate_dkim_record(domain):
    key_file_path = f"/etc/opendkim/keys/{domain}/default.txt"
    if os.path.exists(key_file_path):
        with open(key_file_path) as key_file:
            dkim_record = key_file.read().replace("\n", "")
        return dkim_record
    else:
        return "[clé DKIM non trouvée]"

def backup_file(file_path):
    backup_path = file_path + ".bak"
    subprocess.run(["sudo", "cp", file_path, backup_path])
    print(f"Sauvegarde du fichier {file_path} vers {backup_path}")

def check_prerequisites(log_file):
    required_packages = ["postfix", "mailutils", "libsasl2-modules", "opendkim", "certbot", "ufw"]
    for package in required_packages:
        result = subprocess.run(['dpkg', '-l', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            update_log_page(f"Le paquet {package} n'est pas installé. Installation en cours...", log_file)
            run_command(f"sudo apt-get install {package} -y", log_file)
        else:
            update_log_page(f"Le paquet {package} est déjà installé.", log_file)

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

def install_python_if_needed(log_file):
    try:
        subprocess.run(['python3', '--version'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        update_log_page("Python 3 est déjà installé.", log_file)
    except subprocess.CalledProcessError:
        update_log_page("Python 3 n'est pas installé. Installation en cours...", log_file)
        os_type = detect_os()
        if os_type == "debian":
            run_command("sudo apt-get install python3 -y", log_file)
        elif os_type == "rhel":
            run_command("sudo yum install python3 -y", log_file)
        else:
            update_log_page("Échec de l'installation : distribution non reconnue.", log_file)
            sys.exit(1)

def setup_server(args):
    log_file_path = "/tmp/postfix_setup_log.txt"
    report_file_path = "/tmp/postfix_setup_report.txt"
    create_log_page(log_file_path)

    # Vérification et installation de Python 3 si nécessaire
    install_python_if_needed(log_file_path)

    update_log_page("Vérification des prérequis...", log_file_path)
    check_prerequisites(log_file_path)

    # Détection de la distribution Linux
    os_type = detect_os()
    if os_type == "unknown":
        update_log_page("Distribution Linux non reconnue. Script interrompu.", log_file_path)
        exit(1)
    
    update_log_page(f"Distribution Linux détectée : {os_type.capitalize()}", log_file_path)

    # 1. Préparation du Serveur
    update_log_page("Mise à jour du serveur...", log_file_path)
    if os_type == "debian":
        run_command("sudo apt-get update && sudo apt-get upgrade -y", log_file_path, args.verbose)
    elif os_type == "rhel":
        run_command("sudo yum update -y", log_file_path, args.verbose)

    # 2. Installation des Paquets Nécessaires (vérification déjà faite)
    update_log_page("Installation de Postfix et des paquets nécessaires (si besoin)...", log_file_path)

    # 3. Configuration de Postfix
    hostname = args.hostname or input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")
    while not validate_hostname(hostname):
        print("Nom d'hôte invalide. Veuillez réessayer.")
        hostname = input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")
    
    domain = hostname.split('.', 1)[1]  # Prendre le domaine à partir du hostname
    ip_address = subprocess.getoutput("hostname -I").strip()
    
    external_domain = args.external_domain or input("Est-ce que le domaine est géré par un fournisseur externe ? (oui/non): ").strip().lower()

    main_cf = f"""
myhostname = {hostname}
mydomain = {domain}
myorigin = $mydomain
mydestination = $myhostname, localhost.$mydomain, $mydomain
inet_interfaces = all
inet_protocols = ipv4
smtpd_tls_cert_file=/etc/letsencrypt/live/{hostname}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/{hostname}/privkey.pem
smtpd_use_tls=yes
smtpd_tls_auth_only=yes
smtpd_tls_security_level=encrypt
smtp_tls_security_level=may
smtp_tls_note_starttls_offer=yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname
smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination
"""

    if external_domain == "oui":
        relayhost = input("Entrez le serveur SMTP externe à utiliser comme relayhost (ex: smtp.votre-fournisseur-email.com:587): ")
        main_cf += f"\nrelayhost = [{relayhost}]\n"
        main_cf += "smtp_sasl_auth_enable = yes\n"
        main_cf += "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\n"
        main_cf += "smtp_sasl_security_options = noanonymous\n"
        main_cf += "smtp_tls_security_level = encrypt\n"
        main_cf += "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt\n"
        
        # Créer le fichier des identifiants SMTP
        smtp_user = input("Entrez le nom d'utilisateur SMTP pour le relayhost: ")
        smtp_pass = input("Entrez le mot de passe SMTP pour le relayhost: ")

        with open("/etc/postfix/sasl_passwd", "w") as f:
            f.write(f"[{relayhost}] {smtp_user}:{smtp_pass}\n")

        run_command("sudo postmap /etc/postfix/sasl_passwd", log_file_path, args.verbose)
        run_command("sudo chmod 600 /etc/postfix/sasl_passwd", log_file_path, args.verbose)

    # Sauvegarde du fichier de configuration Postfix
    backup_file("/etc/postfix/main.cf")

    update_log_page("Configuration de Postfix...", log_file_path)
    with open("/etc/postfix/main.cf", "w") as f:
        f.write(main_cf)

    # 4. Configurer l’authentification SMTP (SASL) et TLS
    update_log_page("Obtention et configuration du certificat SSL...", log_file_path)
    run_command(f"sudo certbot certonly --standalone -d {hostname} --non-interactive --agree-tos -m admin@{domain}", log_file_path, args.verbose)

    # 5. Configurer SPF, DKIM et DMARC
    update_log_page("Configuration d'OpenDKIM...", log_file_path)
    trusted_hosts = f"""
127.0.0.1
localhost
{hostname}
"""
    with open("/etc/opendkim/trusted.hosts", "w") as f:
        f.write(trusted_hosts)

    key_table = f"default._domainkey.{domain} {domain}:default:/etc/opendkim/keys/{domain}/default.private\n"
    with open("/etc/opendkim/key.table", "w") as f:
        f.write(key_table)

    signing_table = f"*@{domain} default._domainkey.{domain}\n"
    with open("/etc/opendkim/signing.table", "w") as f:
        f.write(signing_table)

    run_command(f"sudo mkdir -p /etc/opendkim/keys/{domain}", log_file_path, args.verbose)
    run_command(f"sudo opendkim-genkey -D /etc/opendkim/keys/{domain}/ -d {domain} -s default", log_file_path, args.verbose)
    run_command(f"sudo chown opendkim:opendkim /etc/opendkim/keys/{domain}/default.private", log_file_path, args.verbose)

    # 6. Optimiser Postfix pour 10 000 mails par jour
    update_log_page("Optimisation de Postfix pour gérer un volume de 10 000 mails par jour...", log_file_path)
    run_command("sudo postconf -e 'default_process_limit = 100'", log_file_path, args.verbose)
    run_command("sudo postconf -e 'smtpd_client_connection_count_limit = 20'", log_file_path, args.verbose)
    run_command("sudo postconf -e 'smtp_destination_concurrency_limit = 5'", log_file_path, args.verbose)
    run_command("sudo postconf -e 'smtpd_recipient_limit = 100'", log_file_path, args.verbose)

    # 7. Configuration du Monitoring et des Logs
    update_log_page("Configuration des logs Postfix...", log_file_path)
    run_command("sudo sed -i 's/#mail./mail./g' /etc/rsyslog.d/50-default.conf", log_file_path, args.verbose)
    run_command("sudo systemctl restart rsyslog", log_file_path, args.verbose)

    # 8. Sécuriser le Serveur
    update_log_page("Configuration du firewall avec UFW...", log_file_path)
    run_command("sudo ufw allow OpenSSH", log_file_path, args.verbose)
    run_command("sudo ufw allow 'Postfix'", log_file_path, args.verbose)
    run_command("sudo ufw enable", log_file_path, args.verbose)

    update_log_page("Serveur Postfix configuré avec succès!", log_file_path)
    generate_report(report_file_path, hostname, domain, ip_address, external_domain)

    update_log_page(f"Rapport de configuration généré à l'emplacement : {report_file_path}", log_file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de configuration de serveur Postfix")
    parser.add_argument("--hostname", help="Nom d'hôte du serveur de messagerie")
    parser.add_argument("--external-domain", help="Le domaine est-il géré par un fournisseur externe ? (oui/non)")
    parser.add_argument("--verbose", action="store_true", help="Activer le mode verbeux")
    args = parser.parse_args()

    setup_server(args)
