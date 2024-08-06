#!/bin/bash

# Couleurs pour les sorties
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

function print_colored() {
    echo -e "${2}${1}${RESET}"
}

# Demande des paramètres de configuration pour Postfix
print_colored "=== Configuration de Postfix ===" $BLUE
read -p "Nom d'hôte (hostname) pour le serveur SMTP: " hostname
read -p "Nom de domaine (domain) pour le serveur SMTP: " domain
read -p "Adresse e-mail pour les messages sortants (ex: admin@$domain): " email
read -p "Adresse e-mail de destination pour les tests: " test_email

# Mise à jour du système
print_colored "=== Mise à jour du système ===" $BLUE
sudo apt-get update -y && sudo apt-get upgrade -y

# Installation des paquets nécessaires
print_colored "=== Installation des paquets nécessaires ===" $BLUE
sudo apt-get install -y postfix mailutils libsasl2-modules opendkim opendkim-tools certbot ufw bc lsof

# Configuration de Postfix
print_colored "=== Configuration de Postfix ===" $BLUE
sudo postconf -e "myhostname = $hostname"
sudo postconf -e "mydomain = $domain"
sudo postconf -e "myorigin = /etc/mailname"
echo "$domain" | sudo tee /etc/mailname > /dev/null
sudo postconf -e "inet_interfaces = all"
sudo postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
sudo postconf -e "relayhost = "
sudo postconf -e "mynetworks = 127.0.0.0/8"
sudo postconf -e "mailbox_size_limit = 0"
sudo postconf -e "recipient_delimiter = +"
sudo postconf -e "inet_protocols = ipv4"

# Configuration des ports SMTP
print_colored "=== Configuration des ports SMTP (587 et 465) ===" $BLUE
sudo postconf -e "smtpd_tls_security_level = may"
sudo postconf -e "smtpd_tls_auth_only = yes"
sudo postconf -e "smtpd_tls_cert_file=/etc/letsencrypt/live/$domain/fullchain.pem"
sudo postconf -e "smtpd_tls_key_file=/etc/letsencrypt/live/$domain/privkey.pem"
sudo postconf -e "smtpd_use_tls=yes"
sudo postconf -e "smtpd_sasl_auth_enable = yes"
sudo postconf -e "smtpd_sasl_security_options = noanonymous"
sudo postconf -e "broken_sasl_auth_clients = yes"
sudo postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination"

# Configuration des clés DKIM
print_colored "=== Configuration de DKIM ===" $BLUE
sudo mkdir -p /etc/opendkim/keys/$domain
sudo opendkim-genkey -D /etc/opendkim/keys/$domain/ -d $domain -s default
sudo chown -R opendkim:opendkim /etc/opendkim/keys/$domain
mv /etc/opendkim/keys/$domain/default.private /etc/opendkim/keys/$domain/default
cat <<EOF | sudo tee -a /etc/opendkim.conf
AutoRestart             Yes
AutoRestartRate         10/1h
Syslog                  Yes
UMask                   002
OversignHeaders         From
TrustAnchorFile         /usr/share/dns/root.key
KeyTable                /etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
ExternalIgnoreList      /etc/opendkim/trusted.hosts
InternalHosts           /etc/opendkim/trusted.hosts
EOF

cat <<EOF | sudo tee /etc/opendkim/key.table
default._domainkey.$domain $domain:default:/etc/opendkim/keys/$domain/default
EOF

cat <<EOF | sudo tee /etc/opendkim/signing.table
*@${domain} default._domainkey.${domain}
EOF

cat <<EOF | sudo tee /etc/opendkim/trusted.hosts
127.0.0.1
localhost
$domain
EOF

sudo systemctl restart opendkim
sudo systemctl enable opendkim

# Intégration de DKIM avec Postfix
print_colored "=== Intégration de DKIM avec Postfix ===" $BLUE
sudo postconf -e "milter_default_action = accept"
sudo postconf -e "milter_protocol = 6"
sudo postconf -e "smtpd_milters = inet:localhost:8891"
sudo postconf -e "non_smtpd_milters = inet:localhost:8891"

# Configuration de la capture de logs
print_colored "=== Configuration de la capture de logs ===" $BLUE
sudo postconf -e "maillog_file = /var/log/mail.log"
sudo touch /var/log/mail.log
sudo chmod 640 /var/log/mail.log
sudo chown syslog:adm /var/log/mail.log
sudo systemctl restart rsyslog

# Débogage
print_colored "=== Configuration du débogage ===" $BLUE
sudo postconf -e "debug_peer_list = $domain"
sudo postconf -e "debugger_command = PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin"
sudo postconf -e "debugger_command = ${debugger_command} echo 'Postfix debug:'; sleep 1000"

# Ouverture des ports SMTP
print_colored "=== Ouverture des ports 587 et 465 ===" $BLUE
sudo ufw allow 587
sudo ufw allow 465

# Test d'envoi de mail
print_colored "=== Test d'envoi de mail ===" $BLUE
echo "Test de configuration SMTP sur $hostname ($domain)" | mail -s "Test SMTP" "$test_email"

if [ $? -eq 0 ]; then
    print_colored "Test d'envoi de mail réussi. Vérifiez l'email de destination." $GREEN
else
    print_colored "Échec du test d'envoi de mail." $RED
    exit 1
fi

# Génération du fichier smtp.txt
print_colored "=== Génération du fichier smtp.txt ===" $BLUE
echo "SMTP Configuration" > smtp.txt
echo "Hostname: $hostname" >> smtp.txt
echo "Domain: $domain" >> smtp.txt
echo "Ports: 587, 465" >> smtp.txt
echo "DKIM: Configured" >> smtp.txt
echo "Email: $email" >> smtp.txt
echo "Test Email: $test_email" >> smtp.txt
cat smtp.txt

print_colored "=== Configuration terminée ===" $GREEN
