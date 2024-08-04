#!/bin/bash

# Mise à jour du système
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get full-upgrade -y
sudo apt-get install -y python3-pip curl nano python3

echo "System update, upgrade, and installations completed!"

# Demander à l'utilisateur s'il veut exécuter setup_postfix.py
read -p "Lancer l'installation de postfix? (yes/no): " choice

if [ "$choice" == "yes" ] || [ "$choice" == "y" ]; then
    if [ -f "postfix.py" ]; then
        python3 setup_postfix.py
    else
        echo "setup_postfix.py not found!"
    fi
else
    echo "Skipping the execution of setup_postfix.py."
fi
