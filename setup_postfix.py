import os
import subprocess
import sys
import time
import argparse
import shutil

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
            process.wait()
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command)
    except Exception as e:
        handle_error(f"Une erreur s'est produite lors de l'exécution de la commande {command}: {str(e)}", log_file)

def handle_error(message, log_file):
    log_file.write(message + "\n")
    print(message)
    sys.exit(1)

def create_log_page(log_file_path):
    try:
        with open(log_file_path, 'w') as log_file:
            log_file.write("Initialisation du script de configuration du serveur Postfix...\n")
    except IOError as e:
        print(f"Erreur lors de la création du fichier log: {str(e)}")
        sys.exit(1)

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
    try:
        backup_path = file_path + ".bak"
        shutil.copy(file_path, backup_path)
        print(f"Sauvegarde du fichier {file_path} vers {backup_path}")
    except IOError as e:
        print(f"Erreur lors de la sauvegarde du fichier: {str(e)}")
        sys.exit(1)

def check_prerequisites(log_file):
    required_packages = ["postfix", "mailutils", "libsasl2-modules", "opendkim", "certbot", "ufw"]
    for package in required_packages:
        try:
            result = subprocess.run(['dpkg', '-l', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                update_log_page(f"Le paquet {package} n'est pas installé. Installation en cours...", log_file)
                run_command(f"sudo apt-get install {package} -y", log_file)
            else:
                update_log_page(f"Le paquet {package} est déjà installé.", log_file)
        except subprocess.CalledProcessError as e:
            handle_error(f"Erreur lors de la vérification des prérequis: {str(e)}", log_file)

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

def generate_smtp_info_file(smtp_info_file_path, hostname, domain, ip_address, relayhost=None, smtp_user=None, smtp_pass=None):
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
        
        if relayhost:
            smtp_info_file.write(f"- Relayhost : {relayhost}\n")
            if smtp_user and smtp_pass:
                smtp_info_file.write(f"- Nom d'utilisateur : {smtp_user}\n")
                smtp_info_file.write(f"- Mot de passe : {smtp_pass}\n")
        else:
            smtp_info_file.write("- Utilisation directe sans relayhost.\n")
        
        smtp_info_file.write("\nParamètres supplémentaires :\n")
        smtp_info_file.write(f"- SPF : v=spf1 a mx ip4:{ip_address} ~all\n")
        dkim_record = generate_dkim_record(domain)
        smtp_info_file.write(f"- DKIM : default._domainkey.{domain} IN TXT ( \"{dkim_record}\" )\n")
        smtp_info_file.write(f"- DMARC : _dmarc.{domain} IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}\"")

def setup_server(args):
    log_file_path = "/tmp/postfix_setup_log.txt"
    report_file_path = "/tmp/postfix_setup_report.txt"
    smtp_info_file_path = "/tmp/smtp_info.txt"
    
    create_log_page(log_file_path)

    try:
        install_python_if_needed(log_file_path)
        update_log_page("Vérification des prérequis...", log_file_path)
        check_prerequisites(log_file_path)

        os_type = detect_os()
        if os_type == "unknown":
            handle_error("Distribution Linux non reconnue. Script interrompu.", log_file_path)
        
        update_log_page(f"Distribution Linux détectée : {os_type.capitalize()}", log_file_path)

        update_log_page("Mise à jour du serveur...", log_file_path)
        if os_type == "debian":
            run_command("sudo apt-get update && sudo apt-get upgrade -y", log_file_path, args.verbose)
        elif os_type == "rhel":
            run_command("sudo yum update -y", log_file_path, args.verbose)

        update_log_page("Installation de Postfix et des paquets nécessaires (si besoin)...", log_file_path)

        hostname = args.hostname or input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")
        while not validate_hostname(hostname):
            print("Nom d'hôte invalide. Veuillez réessayer.")
            hostname = input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")

        domain = hostname.split('.', 1)[1]
        ip_address = subprocess.getoutput("hostname -I").strip()
        
        external_domain = args.external_domain or input("Est-ce que le domaine est géré par un fournisseur externe ? (oui/non): ").strip().lower()

        relayhost = None
        smtp_user = None
        smtp_pass = None

        if external_domain == "oui":
            relayhost = input("Entrez le serveur SMTP externe à utiliser comme relayhost (ex: smtp.votre-fournisseur-email.com:587): ")
            smtp_user = input("Entrez le nom d'utilisateur SMTP pour le relayhost: ")
            smtp_pass = input("Entrez le mot de passe SMTP pour le relayhost: ")

        configure_postfix(hostname, domain, ip_address, external_domain, relayhost, smtp_user, smtp_pass, log_file_path, args.verbose)
        configure_opendkim(domain, log_file_path, args.verbose)
        optimize_postfix(log_file_path, args.verbose)
        configure_firewall(log_file_path, args.verbose)

        update_log_page("Serveur Postfix configuré avec succès!", log_file_path)
        generate_report(report_file_path, hostname, domain, ip_address, external_domain)
        generate_smtp_info_file(smtp_info_file_path, hostname, domain, ip_address, relayhost, smtp_user, smtp_pass)
        update_log_page(f"Rapport de configuration généré à l'emplacement : {report_file_path}", log_file_path)
        update_log_page(f"Informations SMTP générées à l'emplacement : {smtp_info_file_path}", log_file_path)
    except Exception as e:
        handle_error(f"Échec de la configuration du serveur: {str(e)}", log_file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de configuration de serveur Postfix")
    parser.add_argument("--hostname", help="Nom d'hôte du serveur de messagerie")
    parser.add_argument("--external-domain", help="Le domaine est-il géré par un fournisseur externe ? (oui/non)")
    parser.add_argument("--verbose", action="store_true", help="Activer le mode verbeux")
    args = parser.parse_args()

    setup_server(args)
