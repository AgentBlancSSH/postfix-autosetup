#!/bin/bash

# Fichier de configuration Postfix
MASTER_CF="/etc/postfix/master.cf"

# Fonction pour configurer le port 587 (submission)
configure_submission_port() {
    if grep -q "^#submission inet" $MASTER_CF; then
        echo "Configuration du port 587 (submission)..."
        sed -i "/^#submission inet/s/^#//" $MASTER_CF
        sed -i "/^submission inet/a \ \ -o syslog_name=postfix/submission\n\ \ -o smtpd_tls_security_level=encrypt\n\ \ -o smtpd_sasl_auth_enable=yes\n\ \ -o smtpd_client_restrictions=permit_sasl_authenticated,reject\n\ \ -o milter_macro_daemon_name=ORIGINATING" $MASTER_CF
    else
        echo "Le port 587 est déjà configuré."
    fi
}

# Fonction pour configurer le port 465 (smtps)
configure_smtps_port() {
    if grep -q "^#smtps inet" $MASTER_CF; then
        echo "Configuration du port 465 (smtps)..."
        sed -i "/^#smtps inet/s/^#//" $MASTER_CF
        sed -i "/^smtps inet/a \ \ -o syslog_name=postfix/smtps\n\ \ -o smtpd_tls_wrappermode=yes\n\ \ -o smtpd_sasl_auth_enable=yes\n\ \ -o smtpd_client_restrictions=permit_sasl_authenticated,reject\n\ \ -o milter_macro_daemon_name=ORIGINATING" $MASTER_CF
    else
        echo "Le port 465 est déjà configuré."
    fi
}

# Appliquer les configurations
configure_submission_port
configure_smtps_port

# Recharger la configuration de Postfix
echo "Rechargement de la configuration Postfix..."
sudo postfix reload

echo "Configuration de Postfix pour les ports 587 et 465 terminée."
