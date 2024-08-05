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

# Fonction pour tester la connexion SMTP avec TLS sur le port 587
test_smtp_tls_587() {
    SMTP_HOST="localhost"
    SMTP_PORT=587

    echo "Tentative de connexion à $SMTP_HOST sur le port $SMTP_PORT avec STARTTLS..."
    echo -e "EHLO $SMTP_HOST\nSTARTTLS\nQUIT" | openssl s_client -connect $SMTP_HOST:$SMTP_PORT -starttls smtp > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Connexion TLS au serveur SMTP sur le port 587 réussie."
    else
        echo "Impossible de se connecter au serveur SMTP sur le port 587 avec TLS."
        exit 1
    fi
}

# Fonction pour tester la connexion SMTP avec SSL sur le port 465
test_smtp_ssl_465() {
    SMTP_HOST="localhost"
    SMTP_PORT=465

    echo "Tentative de connexion à $SMTP_HOST sur le port $SMTP_PORT avec SSL..."
    echo -e "EHLO $SMTP_HOST\nQUIT" | openssl s_client -connect $SMTP_HOST:$SMTP_PORT -ssl3 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Connexion SSL au serveur SMTP sur le port 465 réussie."
    else
        echo "Impossible de se connecter au serveur SMTP sur le port 465 avec SSL."
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
test_smtp_tls_587
test_smtp_ssl_465
send_test_email

echo "Vérifications terminées. Si l'email de test est reçu, le serveur SMTP fonctionne correctement sur les ports 587 et 465."
