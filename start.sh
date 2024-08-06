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

# Demander les informations nécessaires
read -p "Nom de domaine (ex: example.com): " domain
read -p "Adresse IP publique de votre serveur SMTP: " server_ip
read -p "Adresse e-mail pour les rapports DMARC (ex: admin@$domain): " dmarc_email

# Vérification de la présence de dig pour DNS checks
if ! command -v dig &> /dev/null
then
    print_colored "dig could not be found, installing it now..." $YELLOW
    sudo apt-get install -y dnsutils
fi

# Vérification de la configuration SPF
print_colored "=== Configuration de l'enregistrement SPF ===" $BLUE
spf_record=$(dig +short TXT $domain | grep spf)

if [ -z "$spf_record" ]; then
    print_colored "Aucun enregistrement SPF trouvé pour $domain." $RED
    print_colored "Vous devez ajouter l'enregistrement suivant à votre DNS:" $GREEN
    echo "v=spf1 mx a ip4:$server_ip -all"
else
    print_colored "Enregistrement SPF existant trouvé:" $GREEN
    echo "$spf_record"
fi

# Vérification de la configuration DKIM
print_colored "=== Vérification de la configuration DKIM ===" $BLUE
dkim_record=$(dig +short TXT default._domainkey.$domain)

if [ -z "$dkim_record" ]; then
    print_colored "Aucun enregistrement DKIM trouvé pour $domain." $RED
    print_colored "Assurez-vous d'ajouter votre clé publique DKIM à votre DNS." $YELLOW
    print_colored "Vous pouvez générer une clé avec la commande suivante sur votre serveur:" $GREEN
    echo "opendkim-genkey -D /etc/opendkim/keys/$domain/ -d $domain -s default"
else
    print_colored "Enregistrement DKIM existant trouvé:" $GREEN
    echo "$dkim_record"
fi

# Configuration DMARC
print_colored "=== Configuration de l'enregistrement DMARC ===" $BLUE
dmarc_record=$(dig +short TXT _dmarc.$domain)

if [ -z "$dmarc_record"; then
    print_colored "Aucun enregistrement DMARC trouvé pour $domain." $RED
    print_colored "Vous devez ajouter l'enregistrement suivant à votre DNS:" $GREEN
    echo "v=DMARC1; p=none; rua=mailto:$dmarc_email"
else
    print_colored "Enregistrement DMARC existant trouvé:" $GREEN
    echo "$dmarc_record"
fi

# Vérification du reverse DNS (PTR)
print_colored "=== Vérification du reverse DNS (PTR) ===" $BLUE
ptr_record=$(dig +short -x $server_ip)

if [[ "$ptr_record" == *"$domain"* ]]; then
    print_colored "Le reverse DNS est correctement configuré: $ptr_record" $GREEN
else
    print_colored "Le reverse DNS n'est pas configuré correctement." $RED
    print_colored "Demandez à votre fournisseur d'hébergement de configurer le PTR pour $server_ip avec le domaine $domain" $YELLOW
fi

# Recommandations pour le contenu de l'e-mail
print_colored "=== Recommandations pour le contenu de l'e-mail ===" $BLUE
echo "1. Utilisez un sujet clair et évitez les mots déclencheurs de spam."
echo "2. Incluez des informations de contact légitimes dans chaque e-mail."
echo "3. Évitez les liens raccourcis et assurez-vous que tous les liens pointent vers des domaines de confiance."
echo "4. Incluez une signature DKIM et respectez les bonnes pratiques SPF/DMARC."
echo "5. Testez régulièrement vos e-mails avec des outils comme Mail-Tester (https://www.mail-tester.com/)."

# Conclusion
print_colored "=== Processus terminé ===" $GREEN
echo "Veuillez suivre les instructions ci-dessus pour vous assurer que vos e-mails ne finissent pas dans les spams."
