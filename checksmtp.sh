#!/bin/bash

# Fonction pour vérifier si Postfix est en cours d'exécution
check_postfix_service() {
    systemctl is-active --quiet postfix
    if [ $? -eq 0 ]; then
        echo "Postfix est en cours d'exécution."
    else
        echo "Postfix n'est pas en cours d'exécution."
        exit 1
    fi
}

# Fonction pour tester la connexion SMTP avec telnet
test_smtp_connection() {
    SMTP_HOST="localhost"
    SMTP_PORT=25

    echo "Tentative de connexion à $SMTP_HOST sur le port $SMTP_PORT..."
    timeout 5 telnet $SMTP_HOST $SMTP_PORT > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Connexion au serveur SMTP réussie."
    else
        echo "Impossible de se connecter au serveur SMTP."
        exit 1
    fi
}

# Fonction pour envoyer un email de test
send_test_email() {
    EMAIL_TO="youremail@example.com"
    EMAIL_SUBJECT="Test de Postfix"
    EMAIL_BODY="Ceci est un email de test envoyé depuis le serveur Postfix."

    echo "Envoi d'un email de test à $EMAIL_TO..."
    echo "$EMAIL_BODY" | mail -s "$EMAIL_SUBJECT" "$EMAIL_TO"
    if [ $? -eq 0 ]; then
        echo "Email de test envoyé avec succès."
    else
        echo "Échec de l'envoi de l'email de test."
        exit 1
    fi
}

# Exécution des fonctions
check_postfix_service
test_smtp_connection
send_test_email

echo "Vérifications terminées. Si l'email de test est reçu, le serveur SMTP fonctionne correctement."
