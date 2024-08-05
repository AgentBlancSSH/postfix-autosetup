#!/bin/bash

# Fonction pour vérifier si un paquet est installé
function check_and_install {
    if ! dpkg -l | grep -qw $1; then
        echo "Le paquet $1 n'est pas installé. Installation en cours..."
        sudo apt-get install -y $1
        if [ $? -ne 0 ]; then
            echo "Erreur lors de l'installation de $1. Arrêt du script."
            exit 1
        fi
    else
        echo "Le paquet $1 est déjà installé."
    fi
}

# Mise à jour du système
sudo apt-get update -y
if [ $? -ne 0 ]; then
    echo "Erreur lors de l'exécution de 'apt-get update'. Arrêt du script."
    exit 1
fi

sudo apt-get upgrade -y
if [ $? -ne 0 ]; then
    echo "Erreur lors de l'exécution de 'apt-get upgrade'. Arrêt du script."
    exit 1
fi

sudo apt-get full-upgrade -y
if [ $? -ne 0 ]; then
    echo "Erreur lors de l'exécution de 'apt-get full-upgrade'. Arrêt du script."
    exit 1
fi

# Installation des paquets essentiels
check_and_install "python3-pip"
check_and_install "curl"
check_and_install "nano"
check_and_install "python3"

echo "Mise à jour du système, mise à niveau et installations complétées !"

# Vérification de la présence de setup_postfix_complete.py avant de demander à l'utilisateur
if [ -f "setup_postfix_complete.py" ]; then
    # Demander à l'utilisateur s'il veut exécuter setup_postfix_complete.py
    read -p "Lancer l'installation de Postfix? (yes/no): " choice
    if [ "$choice" = "yes" ] || [ "$choice" = "y" ]; then
        sudo python3 setup_postfix_complete.py --verbose
        if [ $? -ne 0 ]; then
            echo "Erreur lors de l'exécution de setup_postfix_complete.py. Arrêt du script."
            exit 1
        fi
    else
        echo "Exécution de setup_postfix_complete.py annulée par l'utilisateur."
    fi
else
    echo "setup_postfix_complete.py non trouvé ! Assurez-vous que le fichier est dans le répertoire courant."
    exit 1
fi
