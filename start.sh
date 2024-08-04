#!/bin/bash

# Mise à jour du système
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get full-upgrade -y
sudo apt-get install -y python3-pip curl nano python3

echo "System update, upgrade, and installations completed!"

# Demander à l'utilisateur s'il veut exécuter setup_postfix_complete.py
read -p "Lancer l'installation de Postfix? (yes/no): " choice

if [ "$choice" = "yes" ] || [ "$choice" = "y" ]; then
    if [ -f "setup_postfix_complete.py" ]; then
        sudo python3 setup_postfix_complete.py --verbose
    else
        echo "setup_postfix_complete.py not found!"
    fi
else
    echo "Skipping the execution of setup_postfix_complete.py."
fi
