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

# Function to log progress and errors to a file
LOG_FILE="install.log"
function log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

# Function to handle errors
function handle_error() {
    print_colored "Erreur : $1. Voir le fichier $LOG_FILE pour plus de détails." $RED
    log_message "Erreur : $1"
    exit 1
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
    sudo apt-get update -y && sudo apt-get install -y docker.io || handle_error "Échec de l'installation de Docker"
    sudo systemctl start docker || handle_error "Échec du démarrage de Docker"
    sudo systemctl enable docker || handle_error "Échec de l'activation de Docker au démarrage"
    print_colored "Docker a été installé avec succès." $GREEN
    log_message "Docker installé et démarré avec succès."
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
log_message "Dockerfile créé avec succès."

# Création du script install.sh
# (reprise des éléments du script précédemment intégré)
# ...

# Construction de l'image Docker
print_colored "=== Construction de l'image Docker ===" $BLUE
docker build -t $DOCKER_IMAGE_NAME . || handle_error "Échec de la construction de l'image Docker"
print_colored "Image Docker construite avec succès." $GREEN
log_message "Image Docker construite avec succès."

# Exécution du conteneur
print_colored "=== Exécution du conteneur Docker ===" $BLUE
docker run -d --name $CONTAINER_NAME -p 587:587 -p 465:465 $DOCKER_IMAGE_NAME || handle_error "Échec du démarrage du conteneur Docker"
print_colored "Le conteneur Docker a été démarré avec succès." $GREEN
log_message "Conteneur Docker démarré avec succès."

# Génération du fichier d'identifiants SMTP
print_colored "=== Génération du fichier d'identifiants SMTP ===" $BLUE
cat <<EOF > $SMTP_FILE
SMTP Server: $DOMAIN
SMTP Ports: 587 (submission), 465 (smtps)
SMTP Username: $SMTP_USER
SMTP Password: $SMTP_PASSWORD
EOF
print_colored "Fichier $SMTP_FILE généré avec succès." $GREEN
log_message "Fichier d'identifiants SMTP généré avec succès."

# Affichage des logs du conteneur
print_colored "=== Affichage des logs du conteneur ===" $BLUE
docker logs $CONTAINER_NAME || handle_error "Échec de l'affichage des logs du conteneur"

print_colored "Le script start.sh a été exécuté avec succès." $GREEN
log_message "Script start.sh exécuté avec succès."
