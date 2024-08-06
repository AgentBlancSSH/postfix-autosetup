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

# Demander à l'utilisateur d'entrer les variables nécessaires
read -p "Veuillez entrer votre domaine (ex: example.com): " DOMAIN
read -p "Veuillez entrer votre adresse email pour Certbot (ex: admin@example.com): " EMAIL
read -p "Veuillez entrer le nom d'utilisateur SMTP (ex: smtp_user): " SMTP_USER
SMTP_PASSWORD=$(openssl rand -base64 12)

# Variables d'environnement pour Docker
DOCKER_IMAGE_NAME="postfix_smtp_docker_image"
CONTAINER_NAME="postfix_smtp_container"
SMTP_FILE="smtp_credentials.txt"

# Vérification de Docker
print_colored "=== Vérification de Docker ===" $BLUE
if ! command -v docker &> /dev/null; then
    print_colored "Docker n'est pas installé. Installation en cours..." $YELLOW
    sudo apt-get update -y && sudo apt-get install -y docker.io
    sudo systemctl start docker
    sudo systemctl enable docker
    print_colored "Docker a été installé avec succès." $GREEN
else
    print_colored "Docker est déjà installé." $GREEN
fi

# Création du Dockerfile
print_colored "=== Création du Dockerfile ===" $BLUE
cat <<EOF > Dockerfile
FROM ubuntu:20.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \\
    postfix \\
    mailutils \\
    libsasl2-modules \\
    opendkim \\
    opendkim-tools \\
    certbot \\
    python3 \\
    python3-pip \\
    postfix-policyd-spf-python \\
    python3-authres \\
    python3-dns \\
    python3-spf \\
    python3-spf-engine \\
    curl \\
    nano \\
    ufw \\
    bc \\
    lsof

# Configuration initiale de Postfix pour l'envoi uniquement sur les ports 587 et 465
COPY install.sh /install.sh
RUN chmod +x /install.sh && /install.sh

EXPOSE 587 465

CMD ["postfix", "start-fg"]
EOF
print_colored "Dockerfile créé avec succès." $GREEN

# Génération du script install.sh pour configuration Postfix
print_colored "=== Création du script install.sh ===" $BLUE
cat <<EOF > install.sh
#!/bin/bash

# Configurer Postfix pour agir comme un relais SMTP sortant uniquement sur les ports 587 (submission) et 465 (smtps)
postconf -e 'inet_interfaces = all'
postconf -e 'myhostname = $DOMAIN'
postconf -e 'smtpd_tls_cert_file = /etc/letsencrypt/live/$DOMAIN/fullchain.pem'
postconf -e 'smtpd_tls_key_file = /etc/letsencrypt/live/$DOMAIN/privkey.pem'
postconf -e 'smtpd_use_tls = yes'
postconf -e 'smtp_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_auth_enable = no'
postconf -e 'smtp_sasl_security_options = noanonymous'
postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
postconf -e 'smtp_tls_security_level = encrypt'
postconf -e 'smtpd_tls_security_level = encrypt'  # Ajouté de install.sh
postconf -e 'smtp_tls_note_starttls_offer = yes'
postconf -e 'mynetworks_style = subnet'
postconf -e 'smtp_tls_loglevel = 1'
postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'

# Activer les ports submission (587) et smtps (465)
echo "submission inet n       -       y       -       -       smtpd" >> /etc/postfix/master.cf
echo "  -o syslog_name=postfix/submission" >> /etc/postfix/master.cf
echo "  -o smtpd_tls_security_level=encrypt" >> /etc/postfix/master.cf
echo "  -o smtpd_sasl_auth_enable=yes" >> /etc/postfix/master.cf
echo "  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject" >> /etc/postfix/master.cf

echo "smtps     inet  n       -       y       -       -       smtpd" >> /etc/postfix/master.cf
echo "  -o syslog_name=postfix/smtps" >> /etc/postfix/master.cf
echo "  -o smtpd_tls_wrappermode=yes" >> /etc/postfix/master.cf
echo "  -o smtpd_sasl_auth_enable=yes" >> /etc/postfix/master.cf
echo "  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject" >> /etc/postfix/master.cf

# Générer les certificats SSL avec Certbot
certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos -m $EMAIL

# Configuration du mot de passe SASL
echo "[$DOMAIN]:587 $SMTP_USER:$SMTP_PASSWORD" > /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd

# Installation et configuration d'OpenDKIM pour DKIM
apt-get install -y opendkim opendkim-tools

# Génération des clés DKIM
mkdir -p /etc/opendkim/keys/$DOMAIN
opendkim-genkey -s mail -d $DOMAIN
mv mail.private /etc/opendkim/keys/$DOMAIN/mail.private
mv mail.txt /etc/opendkim/keys/$DOMAIN/mail.txt

# Configuration d'OpenDKIM
cat <<EOF >> /etc/opendkim.conf
Syslog                  yes
UMask                   002
Domain                  *
KeyFile                 /etc/opendkim/keys/$DOMAIN/mail.private
Selector                mail
Mode                    sv
AutoRestart             yes
AutoRestartRate         10/1h
Background              yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
OversignHeaders         From
SOCKET                  inet:8891@localhost
EOF

# Création du fichier TrustedHosts
cat <<EOF >> /etc/opendkim/TrustedHosts
127.0.0.1
localhost
$DOMAIN
EOF

# Configuration de Postfix pour utiliser OpenDKIM
cat <<EOF >> /etc/postfix/main.cf
milter_default_action = accept
milter_protocol = 2
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
EOF

# Ajouter un hook pour redémarrer Postfix et Dovecot après le renouvellement du certificat
HOOK_FILE=/etc/letsencrypt/renewal-hooks/post/postfix.sh
> \$HOOK_FILE
echo '#!/bin/sh' >> \$HOOK_FILE
echo 'service postfix reload' >> \$HOOK_FILE
echo 'service dovecot reload' >> \$HOOK_FILE
chmod +x \$HOOK_FILE

# Redémarrer les services
service opendkim restart
service postfix restart
EOF
print_colored "Script install.sh créé avec succès." $GREEN

# Construction de l'image Docker
print_colored "=== Construction de l'image Docker ===" $BLUE
docker build -t $DOCKER_IMAGE_NAME .
print_colored "Image Docker construite avec succès." $GREEN

# Exécution du conteneur
print_colored "=== Exécution du conteneur Docker ===" $BLUE
docker run -d --name $CONTAINER_NAME -p 587:587 -p 465:465 $DOCKER_IMAGE_NAME
print_colored "Le conteneur Docker a été démarré avec succès." $GREEN

# Génération du fichier d'identifiants SMTP
print_colored "=== Génération du fichier d'identifiants SMTP ===" $BLUE
cat <<EOF > $SMTP_FILE
SMTP Server: $DOMAIN
SMTP Ports: 587 (submission), 465 (smtps)
SMTP Username: $SMTP_USER
SMTP Password: $SMTP_PASSWORD
EOF
print_colored "Fichier $SMTP_FILE généré avec succès." $GREEN

# Affichage des logs du conteneur
print_colored "=== Affichage des logs du conteneur ===" $BLUE
docker logs $CONTAINER_NAME

print_colored "Le script start.sh a été exécuté avec succès." $GREEN
