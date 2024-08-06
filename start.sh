#!/bin/bash

# Variables
MAIN_CF="/etc/postfix/main.cf"
ALIASES="/etc/aliases"
ALIASES_DB="/etc/aliases.db"

# Couleurs pour le terminal
RED="\033[91m"
GREEN="\033[92m"
YELLOW="\033[93m"
BLUE="\033[94m"
ENDC="\033[0m"

# Vérification des droits root
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}Ce script doit être exécuté en tant que root.${ENDC}"
  exit 1
fi

echo -e "${BLUE}=== Correction des problèmes de configuration de Postfix ===${ENDC}"

# 1. Configurer smtpd_relay_restrictions et smtpd_recipient_restrictions
echo -e "${YELLOW}Configuration des restrictions SMTP dans main.cf...${ENDC}"
if grep -q "^smtpd_relay_restrictions" $MAIN_CF; then
    sed -i "s/^smtpd_relay_restrictions.*/smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination/" $MAIN_CF
else
    echo "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination" >> $MAIN_CF
fi

if grep -q "^smtpd_recipient_restrictions" $MAIN_CF; then
    sed -i "s/^smtpd_recipient_restrictions.*/smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination/" $MAIN_CF
else
    echo "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination" >> $MAIN_CF
fi

echo -e "${GREEN}Restrictions SMTP configurées avec succès.${ENDC}"

# 2. Créer /etc/aliases si nécessaire et générer /etc/aliases.db
echo -e "${YELLOW}Vérification et création du fichier /etc/aliases...${ENDC}"
if [ ! -f "$ALIASES" ]; then
    echo "root:   admin@marketingtgv.com" > $ALIASES
    echo -e "${GREEN}Fichier /etc/aliases créé.${ENDC}"
else
    echo -e "${GREEN}Fichier /etc/aliases existe déjà.${ENDC}"
fi

echo -e "${YELLOW}Génération de la base de données d'alias...${ENDC}"
newaliases
echo -e "${GREEN}Base de données d'alias générée avec succès.${ENDC}"

# 3. Désactiver les recherches NIS si activées
echo -e "${YELLOW}Désactivation des recherches NIS si elles sont activées...${ENDC}"
if grep -q "^nis_domain" $MAIN_CF; then
    sed -i "s/^nis_domain/#nis_domain/" $MAIN_CF
    echo -e "${GREEN}Recherches NIS désactivées.${ENDC}"
else
    echo -e "${GREEN}Aucune recherche NIS activée. Aucun changement nécessaire.${ENDC}"
fi

# Redémarrer Postfix
echo -e "${YELLOW}Redémarrage de Postfix...${ENDC}"
systemctl restart postfix
echo -e "${GREEN}Postfix redémarré avec succès.${ENDC}"

echo -e "${BLUE}=== Configuration et correction des problèmes de Postfix terminées ===${ENDC}"

# Exécution du reste du script de configuration Postfix

# Fonction utilitaire pour exécuter une commande système
execute_command() {
    local command="$1"
    local error_message="$2"
    try {
        logging.debug(f"Executing command: {command}")
        subprocess.run(command, shell=True, check=True)
    } catch subprocess.CalledProcessError as e {
        logging.error(f"{error_message}: {e}")
        sys.exit(f"{RED}{error_message}{ENDC}")
    }
}

# Vérification de l'installation de Postfix
check_postfix_installation() {
    logging.info("Checking if Postfix is installed...")
    if [ ! -f "/usr/sbin/postfix" ]; then
        echo -e "${RED}Postfix is not installed. Please install Postfix before running this script.${ENDC}"
        exit 1
    fi
    
    if [ ! -f "/etc/postfix/main.cf" ]; then
        logging.info("Postfix main configuration file not found, creating a default one...")
        execute_command "postconf -d > /etc/postfix/main.cf" "Failed to create default main.cf"
    fi
}

# Validation du nom d'hôte
validate_hostname() {
    local hostname="$1"
    pattern="^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    if [[ ! $hostname =~ $pattern ]]; then
        echo -e "${RED}Invalid hostname: ${hostname}${ENDC}"
        exit 1
    fi
}

# Validation de l'adresse email
validate_email() {
    local email="$1"
    pattern="^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if [[ ! $email =~ $pattern ]]; then
        echo -e "${RED}Invalid email address: ${email}${ENDC}"
        exit 1
    fi
}

# Configuration générale de Postfix
configure_postfix_general() {
    local hostname="$1"
    local email="$2"
    logging.info("Configuring Postfix general settings...")
    declare -A settings=(
        ["myhostname"]="$hostname"
        ["myorigin"]="$email"
        ["mydestination"]="localhost"
        ["inet_interfaces"]="all"
        ["inet_protocols"]="ipv4"
        ["home_mailbox"]="Maildir/"
        ["smtpd_sasl_type"]="dovecot"
        ["smtpd_sasl_path"]="private/auth"
        ["smtpd_sasl_auth_enable"]="yes"
        ["broken_sasl_auth_clients"]="yes"
    )
    for key in "${!settings[@]}"; do
        execute_command "postconf -e '${key} = ${settings[$key]}'" "Failed to set $key"
    done
}

# Configuration des ports SMTP dans master.cf
configure_postfix_ports() {
    logging.info("Configuring Postfix SMTP ports...")
    master_cf_path="/etc/postfix/master.cf"

    ports_config=$(cat <<EOF
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
EOF
    )
    
    echo "$ports_config" >> "$master_cf_path"
    logging.info("Successfully configured Postfix SMTP ports in master.cf.")
}

# Configuration de DKIM
configure_dkim() {
    local domain_name="$1"
    logging.info("Configuring DKIM...")
    execute_command "mkdir -p /etc/opendkim/keys" "Failed to create DKIM keys directory"
    execute_command "opendkim-genkey -s mail -d $domain_name" "Failed to generate DKIM keys"
    execute_command "mv mail.private /etc/opendkim/keys/${domain_name}.private" "Failed to move private key"
    execute_command "mv mail.txt /etc/opendkim/keys/${domain_name}.txt" "Failed to move DKIM record"
    execute_command "chown opendkim:opendkim /etc/opendkim/keys/${domain_name}.private" "Failed to set permissions on private key"

    echo "mail._domainkey.${domain_name} ${domain_name}:mail:/etc/opendkim/keys/${domain_name}.private" >> /etc/opendkim/KeyTable
    echo "*@${domain_name} mail._domainkey.${domain_name}" >> /etc/opendkim/SigningTable
    echo -e "127.0.0.1\nlocalhost\n${domain_name}" >> /etc/opendkim/TrustedHosts

    execute_command "systemctl restart opendkim" "Failed to restart OpenDKIM"
}

# Finalisation de la configuration
finalize_smtp_configuration() {
    logging.info("Finalizing SMTP configuration...")
    execute_command "systemctl restart postfix" "Failed to restart Postfix"
    execute_command "systemctl enable postfix" "Failed to enable Postfix on boot"
    execute_command "systemctl enable opendkim" "Failed to enable OpenDKIM on boot"
}

# Sauvegarde des informations SMTP
save_smtp_info() {
    local domain_name="$1"
    local email="$2"
    logging.info("Saving SMTP information...")
    echo -e "SMTP Server: ${domain_name}\nEmail Address: ${email}\nPorts: 587 (Submission), 465 (SMTPS)" > /etc/postfix/smtp_info.txt
}

# Fonction pour envoyer un e-mail de test
send_test_email() {
    local smtp_server="$1"
    local smtp_port="$2"
    local email_sender="$3"
    local email_recipient="$4"
    logging.info("Sending a test email...")
    subject="Test Email from Postfix Setup Script"
    body="This is a test email sent to confirm that Postfix SMTP is working correctly."
    
    echo -e "Subject: $subject\n\n$body" | sendmail -f "$email_sender" "$email_recipient"

    echo -e "${GREEN}Test email sent successfully.${ENDC}"
}

# Fonction principale
main() {
    echo -e "${BLUE}=== Postfix Setup Script ===${ENDC}"
    read -p "$(echo -e ${YELLOW}Enter the hostname \(e.g., mail.example.com\): ${ENDC})" hostname
    read -p "$(echo -e ${YELLOW}Enter the email address to use: ${ENDC})" email
    domain_name=$(echo "$hostname" | awk -F. '{print $(NF-1)"."$NF}')
    read -p "$(echo -e ${YELLOW}Enter the recipient email address for the test \(e.g., your-email@example.com\): ${ENDC})" test_email
    
    check_postfix_installation
    validate_hostname "$hostname"
    validate_email "$email"
    validate_email "$test_email"

    configure_postfix_general "$hostname" "$email"
    configure_postfix_ports
    configure_dkim "$domain_name"
    finalize_smtp_configuration
    save_smtp_info "$domain_name" "$email"
    
    # Envoi du mail de test
    send_test_email "$hostname" 587 "$email" "$test_email"

    echo -e "${GREEN}Postfix and DKIM have been successfully configured.${ENDC}"
    echo -e "${YELLOW}All details have been saved in /etc/postfix/smtp_info.txt${ENDC}"
}

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Ce script doit être exécuté en tant que root.${ENDC}"
    exit 1
else
    main
fi
