#!/bin/bash

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

echo -e "${BLUE}=== Configuration de Postfix pour l'envoi d'e-mails uniquement ===${ENDC}"

# Variables de configuration
DOMAIN="marketingtgv.com"
HOSTNAME="mail.$DOMAIN"
IP_ADDRESS="153.92.210.103"
EMAIL="admin@$DOMAIN"
DKIM_SELECTOR="mail"

# Fonction pour vérifier les erreurs
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}Une erreur est survenue lors de l'exécution du script.${ENDC}"
        exit 1
    fi
}

# Mise à jour et installation des paquets nécessaires
echo -e "${YELLOW}Mise à jour du système et installation des paquets...${ENDC}"
apt update && apt upgrade -y
check_error

apt install -y postfix opendkim opendkim-tools mailutils
check_error

# Configuration de Postfix
echo -e "${YELLOW}Configuration de Postfix...${ENDC}"

postconf -e "myhostname = $HOSTNAME"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = /etc/mailname"
postconf -e "relayhost ="
postconf -e "inet_interfaces = loopback-only"
postconf -e "inet_protocols = ipv4"
postconf -e "smtpd_banner = \$myhostname ESMTP \$mail_name"
postconf -e "biff = no"
postconf -e "append_dot_mydomain = no"
postconf -e "readme_directory = no"
postconf -e "smtpd_use_tls = yes"
postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem"
postconf -e "smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key"
postconf -e "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache"
postconf -e "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache"
postconf -e "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_loglevel = 1"
postconf -e "smtpd_tls_received_header = yes"
postconf -e "smtpd_tls_session_cache_timeout = 3600s"
postconf -e "myhostname = $HOSTNAME"
check_error

echo "$DOMAIN" > /etc/mailname
check_error

# Fonction pour configurer DKIM
configure_dkim() {
    echo -e "${YELLOW}Configuration de DKIM...${ENDC}"

    mkdir -p /etc/opendkim/keys/$DOMAIN
    check_error

    opendkim-genkey -s $DKIM_SELECTOR -d $DOMAIN
    check_error

    mv $DKIM_SELECTOR.private /etc/opendkim/keys/$DOMAIN/
    mv $DKIM_SELECTOR.txt /etc/opendkim/keys/$DOMAIN/
    check_error

    cat > /etc/opendkim.conf <<EODKIM
Syslog                  yes
UMask                   002
Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
Selector                $DKIM_SELECTOR
Socket                  inet:12301@localhost
PidFile                 /var/run/opendkim/opendkim.pid
UserID                  opendkim:opendkim
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
EODKIM
    check_error

    cat > /etc/opendkim/KeyTable <<EOF
$DKIM_SELECTOR._domainkey.$DOMAIN $DOMAIN:$DKIM_SELECTOR:/etc/opendkim/keys/$DOMAIN/$DKIM_SELECTOR.private
EOF
    check_error

    cat > /etc/opendkim/SigningTable <<EOF
*@${DOMAIN} $DKIM_SELECTOR._domainkey.${DOMAIN}
EOF
    check_error

    cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
$DOMAIN
EOF
    check_error

    systemctl restart opendkim
    check_error

    systemctl enable opendkim
    check_error
}

# Appel de la fonction de configuration DKIM
configure_dkim

# Configuration de Postfix pour utiliser DKIM
echo -e "${YELLOW}Configuration de Postfix pour utiliser DKIM...${ENDC}"
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:localhost:12301"
postconf -e "non_smtpd_milters = inet:localhost:12301"
check_error

systemctl restart postfix
check_error

systemctl enable postfix
check_error

echo -e "${GREEN}=== Configuration de Postfix et DKIM terminée ===${ENDC}"

# Test d'envoi d'e-mail
read -p "$(echo -e ${YELLOW}Entrez l'adresse e-mail de destination pour le test: ${ENDC})" test_email
echo -e "Subject: Test SMTP\n\nCeci est un e-mail de test." | sendmail $test_email
check_error

echo -e "${GREEN}E-mail de test envoyé à $test_email${ENDC}"

# Vérifier les logs pour confirmer l'envoi
echo -e "${YELLOW}Vérifiez les logs Postfix pour confirmer l'envoi de l'e-mail :${ENDC}"
tail -f /var/log/mail.log
