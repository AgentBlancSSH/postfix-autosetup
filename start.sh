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

# Vérification de la présence du script Python
if [ ! -f "setup_postfix_complete.py" ]; then
    print_colored "Erreur: Le fichier setup_postfix_complete.py n'existe pas dans le répertoire courant." $RED
    exit 1
else
    print_colored "Le fichier setup_postfix_complete.py a été trouvé." $GREEN
fi

# Mise à jour du système
print_colored "=== Mise à jour du système ===" $BLUE
sudo apt-get update -y && sudo apt-get upgrade -y

# Installation des paquets nécessaires
print_colored "=== Installation des paquets nécessaires ===" $BLUE
sudo apt-get install -y python3-pip curl nano python3 postfix mailutils libsasl2-modules opendkim opendkim-tools certbot ufw bc lsof

# Installation des modules Python spécifiques pour Postfix
print_colored "=== Installation des modules Python spécifiques pour Postfix ===" $BLUE
sudo apt-get install -y postfix-policyd-spf-python python3-authres python3-dns python3-spf python3-spf-engine

# Vérification des installations
print_colored "=== Vérification des paquets installés ===" $BLUE
declare -a packages=("python3-pip" "curl" "nano" "python3" "postfix" "mailutils" "libsasl2-modules" "opendkim" "opendkim-tools" "certbot" "ufw" "bc" "lsof" "postfix-policyd-spf-python" "python3-authres" "python3-dns" "python3-spf" "python3-spf-engine")

for package in "${packages[@]}"; do
    dpkg -l | grep -qw $package
    if [ $? -eq 0 ]; then
        print_colored "$package est déjà installé." $GREEN
    else
        print_colored "$package n'a pas été installé correctement." $RED
        exit 1
    fi
done

# Vérification de la version de Python
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
    print_colored "Python 3.8 ou une version ultérieure est requis. Version actuelle: $PYTHON_VERSION" $RED
    exit 1
else
    print_colored "Version de Python vérifiée: $PYTHON_VERSION" $GREEN
fi

# Vérification des ports critiques
print_colored "=== Vérification des ports 587 et 465 ===" $BLUE
if sudo lsof -i -P -n | grep -q ':587\|:465'; then
    print_colored "Attention: Un service utilise déjà les ports 587 ou 465." $RED
    read -p "$(echo -e ${YELLOW}Voulez-vous continuer malgré cela? (yes/no): ${RESET})" port_choice
    if [[ "$port_choice" != "yes" && "$port_choice" != "y" ]]; then
        print_colored "Exécution annulée." $YELLOW
        exit 1
    fi
else
    print_colored "Les ports 587 et 465 sont disponibles." $GREEN
fi

# Donner les permissions d'exécution au script Python
print_colored "=== Configuration des permissions du script Python ===" $BLUE
chmod +x setup_postfix_complete.py
if [ $? -ne 0 ]; then
    print_colored "Erreur lors de la configuration des permissions pour setup_postfix_complete.py" $RED
    exit 1
fi

# Exécution du script Python avec diagnostic
print_colored "=== Exécution du script Python avec diagnostic ===" $BLUE
if ! sudo python3 setup_postfix_complete.py > setup_postfix_output.log 2>&1; then
    print_colored "Erreur lors de l'exécution du script Python. Veuillez consulter setup_postfix_output.log pour plus de détails." $RED
    exit 1
else
    print_colored "Le script setup_postfix_complete.py a été exécuté avec succès." $GREEN
fi

# Vérification du fichier de log si le script Python n'a pas fonctionné
if [ ! -f "setup_postfix_output.log" ]; then
    print_colored "Erreur: Le fichier de log setup_postfix_output.log n'a pas été créé. Cela peut indiquer que le script Python n'a pas démarré." $RED
    exit 1
else
    print_colored "Le fichier setup_postfix_output.log a été créé. Vous pouvez vérifier son contenu en utilisant 'cat setup_postfix_output.log'" $GREEN
fi

# Afficher la sortie du log pour les utilisateurs
print_colored "=== Contenu du fichier de log ===" $BLUE
cat setup_postfix_output.log
