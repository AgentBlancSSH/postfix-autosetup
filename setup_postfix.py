import os
import subprocess
import sys
import argparse
import shutil

def executer_commande(command, fichier_log, verbose=False):
    try:
        with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                fichier_log.write(line)
                if verbose:
                    print(line, end='')
            for error in process.stderr:
                fichier_log.write(error)
                if verbose:
                    print(f"Erreur : {error}", end='')
            process.wait()
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command)
    except Exception as e:
        gerer_erreur(f"Une erreur s'est produite lors de l'exécution de la commande {command}: {str(e)}", fichier_log)

def gerer_erreur(message, fichier_log):
    fichier_log.write(message + "\n")
    print(message)
    sys.exit(1)

def creer_fichier_log(chemin_fichier_log):
    try:
        with open(chemin_fichier_log, 'w') as fichier_log:
            fichier_log.write("Initialisation du script de configuration du serveur Postfix...\n")
    except IOError as e:
        print(f"Erreur lors de la création du fichier log: {str(e)}")
        sys.exit(1)

def mise_a_jour_fichier_log(message, chemin_fichier_log):
    with open(chemin_fichier_log, 'a') as fichier_log:
        fichier_log.write(message + "\n")
    print(message)

def generer_rapport(chemin_rapport, nom_hote, domaine, adresse_ip, domaine_externe):
    enregistrement_dkim = generer_enregistrement_dkim(domaine)
    with open(chemin_rapport, 'w') as rapport:
        rapport.write(f"Rapport de configuration du serveur Postfix\n")
        rapport.write(f"=============================================\n")
        rapport.write(f"Nom d'hôte : {nom_hote}\n")
        rapport.write(f"Domaine : {domaine}\n")
        rapport.write(f"Adresse IP : {adresse_ip}\n")
        
        if domaine_externe == "oui":
            rapport.write(f"\nLe domaine est géré par un fournisseur externe. Voici les configurations DNS à effectuer chez votre fournisseur DNS:\n")
        else:
            rapport.write(f"\nConfigurations DNS recommandées :\n")

        rapport.write(f"- SPF : v=spf1 a mx ip4:{adresse_ip} ~all\n")
        rapport.write(f"- DKIM : default._domainkey.{domaine} IN TXT ( \"{enregistrement_dkim}\" )\n")
        rapport.write(f"- DMARC : _dmarc.{domaine} IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domaine}\"")

def generer_enregistrement_dkim(domaine):
    chemin_cle = f"/etc/opendkim/keys/{domaine}/default.txt"
    if os.path.exists(chemin_cle):
        with open(chemin_cle) as fichier_cle:
            enregistrement_dkim = fichier_cle.read().replace("\n", "")
        return enregistrement_dkim
    else:
        return "[clé DKIM non trouvée]"

def sauvegarder_fichier(chemin_fichier):
    try:
        chemin_sauvegarde = chemin_fichier + ".bak"
        shutil.copy(chemin_fichier, chemin_sauvegarde)
        print(f"Sauvegarde du fichier {chemin_fichier} vers {chemin_sauvegarde}")
    except IOError as e:
        print(f"Erreur lors de la sauvegarde du fichier: {str(e)}")
        sys.exit(1)

def verifier_prerequis(fichier_log):
    paquets_requis = ["postfix", "mailutils", "libsasl2-modules", "opendkim", "certbot", "ufw"]
    for paquet in paquets_requis:
        try:
            result = subprocess.run(['dpkg', '-l', paquet], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                mise_a_jour_fichier_log(f"Le paquet {paquet} n'est pas installé. Installation en cours...", fichier_log)
                executer_commande(f"sudo apt-get install {paquet} -y", fichier_log)
            else:
                mise_a_jour_fichier_log(f"Le paquet {paquet} est déjà installé.", fichier_log)
        except subprocess.CalledProcessError as e:
            gerer_erreur(f"Erreur lors de la vérification des prérequis: {str(e)}", fichier_log)

def detecter_os():
    with open("/etc/os-release") as f:
        infos_os = f.read().lower()
        if "ubuntu" in infos_os ou "debian" in infos_os:
            return "debian"
        elif "centos" in infos_os ou "rhel" in infos_os:
            return "rhel"
        else:
            return "inconnu"

def valider_nom_hote(nom_hote):
    import re
    if re.match(r'^[a-zA-Z0-9.-]+$', nom_hote):
        return True
    return False

def generer_fichier_smtp(chemin_fichier_smtp, nom_hote, domaine, adresse_ip, relayhost=None, utilisateur_smtp=None, mot_de_passe_smtp=None):
    with open(chemin_fichier_smtp, 'w') as fichier_smtp:
        fichier_smtp.write(f"Informations SMTP pour le serveur {nom_hote}\n")
        fichier_smtp.write(f"=============================================\n")
        fichier_smtp.write(f"Nom d'hôte : {nom_hote}\n")
        fichier_smtp.write(f"Domaine : {domaine}\n")
        fichier_smtp.write(f"Adresse IP : {adresse_ip}\n")
        fichier_smtp.write("\nConfiguration SMTP :\n")
        fichier_smtp.write(f"- SMTP Server : {nom_hote}\n")
        fichier_smtp.write(f"- Port : 587\n")
        fichier_smtp.write(f"- TLS : Oui\n")
        
        if relayhost:
            fichier_smtp.write(f"- Relayhost : {relayhost}\n")
            if utilisateur_smtp et mot_de_passe_smtp:
                fichier_smtp.write(f"- Nom d'utilisateur : {utilisateur_smtp}\n")
                fichier_smtp.write(f"- Mot de passe : {mot_de_passe_smtp}\n")
        else:
            fichier_smtp.write("- Utilisation directe sans relayhost.\n")
        
        fichier_smtp.write("\nParamètres supplémentaires :\n")
        fichier_smtp.write(f"- SPF : v=spf1 a mx ip4:{adresse_ip} ~all\n")
        enregistrement_dkim = generer_enregistrement_dkim(domaine)
        fichier_smtp.write(f"- DKIM : default._domainkey.{domaine} IN TXT ( \"{enregistrement_dkim}\" )\n")
        fichier_smtp.write(f"- DMARC : _dmarc.{domaine} IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domaine}\"")
    
    print(f"Fichier SMTP info généré à : {chemin_fichier_smtp}")

def configurer_postfix(nom_hote, domaine, adresse_ip, domaine_externe, relayhost, utilisateur_smtp, mot_de_passe_smtp, fichier_log, verbose):
    fichier_main_cf = "/etc/postfix/main.cf"
    sauvegarder_fichier(fichier_main_cf)
    
    with open(fichier_main_cf, 'a') as config_postfix:
        config_postfix.write("\n# Configuration Postfix\n")
        config_postfix.write(f"myhostname = {nom_hote}\n")
        config_postfix.write(f"mydomain = {domaine}\n")
        config_postfix.write("myorigin = $mydomain\n")
        config_postfix.write("inet_interfaces = all\n")
        config_postfix.write("inet_protocols = ipv4\n")
        config_postfix.write(f"smtpd_tls_cert_file=/etc/letsencrypt/live/{domaine}/fullchain.pem\n")
        config_postfix.write(f"smtpd_tls_key_file=/etc/letsencrypt/live/{domaine}/privkey.pem\n")
        config_postfix.write("smtpd_use_tls=yes\n")
        config_postfix.write("smtpd_tls_auth_only = yes\n")
        config_postfix.write("smtp_tls_security_level = may\n")
        config_postfix.write("smtp_tls_note_starttls_offer = yes\n")
        config_postfix.write("smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination\n")
        config_postfix.write(f"mydestination = {nom_hote}, localhost.{domaine}, localhost\n")
        config_postfix.write("relayhost = \n" if not relayhost else f"relayhost = [{relayhost}]:587\n")
        config_postfix.write("mynetworks = 127.0.0.0/8 [::1]/128\n")
        config_postfix.write("mailbox_size_limit = 0\n")
        config_postfix.write("recipient_delimiter = +\n")
        config_postfix.write("smtpd_sasl_type = dovecot\n")
        config_postfix.writeDésolé, il semble que la réponse ait été coupée. Je vais continuer avec la partie manquante du script :

```python
        config_postfix.write("smtpd_sasl_path = private/auth\n")
        config_postfix.write("smtpd_sasl_auth_enable = yes\n")
        config_postfix.write("smtpd_sasl_security_options = noanonymous\n")
        config_postfix.write("smtpd_sasl_local_domain = $myhostname\n")
        config_postfix.write("smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination\n")
    
    if utilisateur_smtp and mot_de_passe_smtp:
        with open('/etc/postfix/sasl_passwd', 'w') as fichier_sasl:
            fichier_sasl.write(f"[{relayhost}]:587 {utilisateur_smtp}:{mot_de_passe_smtp}\n")
        executer_commande("sudo postmap /etc/postfix/sasl_passwd", fichier_log, verbose)
        executer_commande("sudo chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db", fichier_log, verbose)
    
    executer_commande("sudo systemctl restart postfix", fichier_log, verbose)

def configurer_opendkim(domaine, fichier_log, verbose):
    executer_commande("sudo apt-get install opendkim opendkim-tools -y", fichier_log, verbose)

    executer_commande(f"sudo mkdir -p /etc/opendkim/keys/{domaine}", fichier_log, verbose)
    executer_commande(f"sudo opendkim-genkey -s default -d {domaine}", fichier_log, verbose)
    executer_commande(f"sudo mv default.private /etc/opendkim/keys/{domaine}/", fichier_log, verbose)
    executer_commande(f"sudo mv default.txt /etc/opendkim/keys/{domaine}/", fichier_log, verbose)
    executer_commande("sudo chown -R opendkim:opendkim /etc/opendkim/keys", fichier_log, verbose)

    with open("/etc/opendkim.conf", "a") as config_opendkim:
        config_opendkim.write("\n# Configuration OpenDKIM\n")
        config_opendkim.write("AutoRestart             Yes\n")
        config_opendkim.write("AutoRestartRate         10/1h\n")
        config_opendkim.write("SyslogSuccess           Yes\n")
        config_opendkim.write("LogWhy                  Yes\n")
        config_opendkim.write("Canonicalization        relaxed/simple\n")
        config_opendkim.write("ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts\n")
        config_opendkim.write("InternalHosts           refile:/etc/opendkim/TrustedHosts\n")
        config_opendkim.write(f"KeyTable                refile:/etc/opendkim/KeyTable\n")
        config_opendkim.write(f"SigningTable            refile:/etc/opendkim/SigningTable\n")
        config_opendkim.write(f"Socket                  inet:8891@localhost\n")
        config_opendkim.write(f"UserID                  opendkim\n")
        config_opendkim.write(f"UMask                   002\n")

    with open("/etc/opendkim/KeyTable", "w") as key_table:
        key_table.write(f"default._domainkey.{domaine} {domaine}:default:/etc/opendkim/keys/{domaine}/default.private\n")

    with open("/etc/opendkim/SigningTable", "w") as signing_table:
        signing_table.write(f"*@{domaine} default._domainkey.{domaine}\n")

    with open("/etc/opendkim/TrustedHosts", "w") as trusted_hosts:
        trusted_hosts.write("127.0.0.1\n")
        trusted_hosts.write("localhost\n")
        trusted_hosts.write(f"{domaine}\n")

    executer_commande("sudo sed -i '/^#milter_protocol = 2/c\milter_protocol = 2' /etc/postfix/main.cf", fichier_log, verbose)
    executer_commande("sudo sed -i '/^#milter_default_action = accept/c\milter_default_action = accept' /etc/postfix/main.cf", fichier_log, verbose)
    executer_commande("sudo sed -i '/^#smtpd_milters/c\smtpd_milters = inet:localhost:8891' /etc/postfix/main.cf", fichier_log, verbose)
    executer_commande("sudo sed -i '/^#non_smtpd_milters/c\non_smtpd_milters = inet:localhost:8891' /etc/postfix/main.cf", fichier_log, verbose)

    executer_commande("sudo systemctl restart opendkim", fichier_log, verbose)
    executer_commande("sudo systemctl restart postfix", fichier_log, verbose)

def optimiser_postfix(fichier_log, verbose):
    executer_commande("sudo postconf -e 'maximal_queue_lifetime = 1d'", fichier_log, verbose)
    executer_commande("sudo postconf -e 'bounce_queue_lifetime = 1d'", fichier_log, verbose)
    executer_commande("sudo postconf -e 'smtp_tls_security_level = may'", fichier_log, verbose)
    executer_commande("sudo postconf -e 'smtpd_tls_security_level = may'", fichier_log, verbose)
    executer_commande("sudo postconf -e 'smtp_tls_note_starttls_offer = yes'", fichier_log, verbose)
    executer_commande("sudo postconf -e 'smtpd_tls_cert_file=/etc/letsencrypt/live/$(hostname)/fullchain.pem'", fichier_log, verbose)
    executer_commande("sudo postconf -e 'smtpd_tls_key_file=/etc/letsencrypt/live/$(hostname)/privkey.pem'", fichier_log, verbose)
    executer_commande("sudo systemctl reload postfix", fichier_log, verbose)

def configurer_pare_feu(fichier_log, verbose):
    executer_commande("sudo ufw allow 25/tcp", fichier_log, verbose)
    executer_commande("sudo ufw allow 465/tcp", fichier_log, verbose)
    executer_commande("sudo ufw allow 587/tcp", fichier_log, verbose)
    executer_commande("sudo ufw enable", fichier_log, verbose)

def setup_server(args):
    chemin_fichier_log = "/tmp/postfix_setup_log.txt"
    chemin_rapport = "/tmp/postfix_setup_report.txt"
    chemin_fichier_smtp = "/tmp/smtp_info.txt"
    
    creer_fichier_log(chemin_fichier_log)

    try:
        mise_a_jour_fichier_log("Vérification des prérequis...", chemin_fichier_log)
        verifier_prerequis(chemin_fichier_log)

        os_type = detecter_os()
        if os_type == "inconnu":
            gerer_erreur("Distribution Linux non reconnue. Script interrompu.", chemin_fichier_log)
        
        mise_a_jour_fichier_log(f"Distribution Linux détectée : {os_type.capitalize()}", chemin_fichier_log)

        mise_a_jour_fichier_log("Mise à jour du serveur...", chemin_fichier_log)
        if os_type == "debian":
            executer_commande("sudo apt-get update && sudo apt-get upgrade -y", chemin_fichier_log, args.verbose)
        elif os_type == "rhel":
            executer_commande("sudo yum update -y", chemin_fichier_log, args.verbose)

        mise_a_jour_fichier_log("Installation de Postfix et des paquets nécessaires (si besoin)...", chemin_fichier_log)

        nom_hote = input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")
        while not valider_nom_hote(nom_hote):
            print("Nom d'hôte invalide. Veuillez réessayer.")
            nom_hote = input("Entrez le nom d'hôte pour le serveur mail (ex: mail.votre-domaine.com): ")

        domaine = nom_hote.split('.', 1)[1]
        adresse_ip = subprocess.getoutput("hostname -I").strip()
        
        domaine_externe = input("Est-ce que le domaine est géré par un fournisseur externe ? (oui/non): ").strip().lower()

        relayhost = None
        utilisateur_smtp = None
        mot_de_passe_smtp = None

        if domaine_externe == "oui":
            relayhost = input("Entrez le serveur SMTP externe à utiliser comme relayhost (ex: smtp.votre-fournisseur-email.com:587): ")
            utilisateur_smtp = input("Entrez le nom d'utilisateur SMTP pour le relayhost: ")
            mot_de_passe_smtp = input("Entrez le mot de passe SMTP pour le relayhost: ")

        configurer_postfix(nom_hote, domaine, adresse_ip, domaine_externe, relayhost, utilisateur_smtp, mot_de_passe_smtp, chemin_fichier_log, args.verbose)
        configurer_opendkim(domaine, chemin_fichier_log, args.verbose)
        optimiser_postfix(chemin_fichier_log, args.verbose)
        configurer_pare_feu(chemin_fichier_log, args.verbose)

        mise_a_jour_fichier_log("Serveur Postfix configuré avec succès!", chemin_fichier_log)
        generer_rapport(chemin_rapport, nom_hote, domaine, adresse_ip, domaine_externe)
        generer_fichier_smtp(chemin_fichier_smtp, nom_hoteVoici la fin du script complet en français :

```python
        generer_fichier_smtp(chemin_fichier_smtp, nom_hote, domaine, adresse_ip, relayhost, utilisateur_smtp, mot_de_passe_smtp)
        mise_a_jour_fichier_log(f"Rapport de configuration généré à l'emplacement : {chemin_rapport}", chemin_fichier_log)
        mise_a_jour_fichier_log(f"Informations SMTP générées à l'emplacement : {chemin_fichier_smtp}", chemin_fichier_log)
    except Exception as e:
        gerer_erreur(f"Échec de la configuration du serveur: {str(e)}", chemin_fichier_log)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de configuration de serveur Postfix")
    parser.add_argument("--verbose", action="store_true", help="Activer le mode verbeux")
    args = parser.parse_args()

    setup_server(args)
