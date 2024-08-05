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

# Mise à jour du système
print_colored "=== Mise à jour du système ===" $BLUE
sudo apt-get update -y && sudo apt-get upgrade -y

# Installation des paquets nécessaires, y compris bc et lsof
print_colored "=== Installation des paquets nécessaires ===" $BLUE
sudo apt-get install -y python3-pip curl nano python3 postfix mailutils libsasl2-modules opendkim opendkim-tools certbot ufw bc lsof

# Vérification des installations
print_colored "=== Vérification des paquets installés ===" $BLUE
declare -a packages=("python3-pip" "curl" "nano" "python3" "postfix" "mailutils" "libsasl2-modules" "opendkim" "opendkim-tools" "certbot" "ufw" "bc" "lsof")

for package in "${packages[@]}"; do
    dpkg -l | grep -qw $package
    if [ $? -eq 0 ]; then
        print_colored "$package est déjà installé." $GREEN
    else
        print_colored "$package n'a pas été installé correctement." $RED
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

# Vérification des ports critiques 587 et 465
print_colored "=== Vérification des ports 587 et 465 ===" $BLUE
if sudo lsof -i -P -n | grep -q ':587\|:465'; then
    print_colored "Attention: Un service utilise déjà les ports 587 ou 465." $RED
    read -p "$(echo -e ${YELLOW}Voulez-vous continuer quand même? (yes/no): ${RESET})" port_choice
    if [[ "$port_choice" != "yes" && "$port_choice" != "y" ]]; then
        print_colored "Exécution annulée." $YELLOW
        exit 1
    fi
else
    print_colored "Les ports 587 et 465 sont disponibles." $GREEN
fi

# Lancer le script Python setup_postfix_complete.py
if [ -f "setup_postfix_complete.py" ]; then
    print_colored "Lancement de la configuration de Postfix..." $BLUE
    sudo python3 setup_postfix_complete.py
else
    print_colored "setup_postfix_complete.py non trouvé ! Assurez-vous que le fichier est dans le répertoire courant." $RED
fi
