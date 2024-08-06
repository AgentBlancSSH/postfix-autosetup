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

# Variables d'environnement
DOMAIN="yourdomain.com"
EMAIL="admin@yourdomain.com"
DOCKER_IMAGE_NAME="postfix_smtp_docker_image"
CONTAINER_NAME="postfix_smtp_container"
SMTP_USER="smtp_user"
SMTP_PASSWORD=$(openssl rand -base64 12)
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

RUN apt-get update && apt-get install -y \\
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

# Configuration initiale de Postfix pour l'envoi uniquement
COPY install.sh /install.sh
RUN chmod +x /install.sh && /install.sh

EXPOSE 25 587 465

CMD ["postfix", "start-fg"]
EOF
print_colored "Dockerfile créé avec succès." $GREEN

# Génération du script install.sh pour configuration Postfix
print_colored "=== Création du script install.sh ===" $BLUE
cat <<EOF > install.sh
#!/bin/bash

# Configurer Postfix pour agir comme un relais SMTP sortant uniquement
postconf -e 'inet_interfaces = loopback-only'
postconf -e 'myhostname = $DOMAIN'
postconf -e 'mydestination ='
postconf -e 'relayhost ='
postconf -e 'smtpd_tls_cert_file = /etc/letsencrypt/live/$DOMAIN/fullchain.pem'
postconf -e 'smtpd_tls_key_file = /etc/letsencrypt/live/$DOMAIN/privkey.pem'
postconf -e 'smtpd_use_tls = yes'
postconf -e 'smtp_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_auth_enable = no'
postconf -e 'smtp_sasl_security_options = noanonymous'
postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
postconf -e 'smtp_tls_security_level = encrypt'
postconf -e 'smtp_tls_note_starttls_offer = yes'
postconf -e 'mynetworks_style = host'
postconf -e 'smtp_tls_loglevel = 1'
postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'

# Générer les certificats SSL avec Certbot
certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos -m $EMAIL

# Configuration du mot de passe SASL
echo "[$DOMAIN]:587 $SMTP_USER:$SMTP_PASSWORD" > /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd

# Relancer Postfix pour prendre en compte les nouvelles configurations
service postfix restart
EOF
print_colored "Script install.sh créé avec succès." $GREEN

# Construction de l'image Docker
print_colored "=== Construction de l'image Docker ===" $BLUE
docker build -t $DOCKER_IMAGE_NAME .
print_colored "Image Docker construite avec succès." $GREEN

# Exécution du conteneur
print_colored "=== Exécution du conteneur Docker ===" $BLUE
docker run -d --name $CONTAINER_NAME -p 25:25 -p 587:587 -p 465:465 $DOCKER_IMAGE_NAME
print_colored "Le conteneur Docker a été démarré avec succès." $GREEN

# Génération du fichier d'identifiants SMTP
print_colored "=== Génération du fichier d'identifiants SMTP ===" $BLUE
cat <<EOF > $SMTP_FILE
SMTP Server: $DOMAIN
SMTP Port: 587
SMTP Username: $SMTP_USER
SMTP Password: $SMTP_PASSWORD
EOF
print_colored "Fichier $SMTP_FILE généré avec succès." $GREEN

# Affichage des logs du conteneur
print_colored "=== Affichage des logs du conteneur ===" $BLUE
docker logs $CONTAINER_NAME

print_colored "Le script start.sh a été exécuté avec succès." $GREEN
