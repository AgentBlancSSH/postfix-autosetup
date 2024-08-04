#!/bin/bash

# Update the package list
sudo apt-get update

# Upgrade the installed packages
sudo apt-get upgrade -y

# Perform a full upgrade
sudo apt-get full-upgrade -y

# Install packages
sudo apt-get install -y python3-pip curl nano python3

echo "System update, upgrade, and installations completed!"

# Ask the user if they want to run postfix.py
read -p "Lancer l'installation de postfix? (yes/no): " choice

if [ "$choice" == "yes" ] || [ "$choice" == "y" ]; then
    if [ -f "postfix.py" ]; then
        python3 postfix.py
    else
        echo "postfix.py not found!"
    fi
else
    echo "Skipping the execution of postfix.py."
fi
