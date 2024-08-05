#!/bin/bash

# Fonction pour vérifier si un paquet est installé, sinon l'installer
check_and_install() {
    PACKAGE=$1
    dpkg -s $PACKAGE &> /dev/null

    if [ $? -ne 0 ]; then
        echo "Installing $PACKAGE..."
        apt-get update && apt-get install -y $PACKAGE
    else
        echo "$PACKAGE is already installed."
    fi
}

# Mise à jour du système et installation des paquets requis
echo "Updating system and installing required packages..."
apt-get update && apt-get upgrade -y

# Vérifier et installer les dépendances
check_and_install "python3"
check_and_install "python3-pip"
check_and_install "postfix"
check_and_install "mailutils"
check_and_install "opendkim"
check_and_install "opendkim-tools"
check_and_install "curl"
check_and_install "nano"
check_and_install "ufw"
check_and_install "bc"
check_and_install "lsof"

# Exécution du script Python
echo "Starting Postfix setup script..."
python3 setup_postfix.py
