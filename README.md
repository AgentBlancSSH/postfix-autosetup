Script de Configuration Automatique d'un Serveur Postfix


Ce script configure automatiquement un serveur de messagerie Postfix sur un serveur Linux.
Il est conçu pour être facile à utiliser, même pour les débutants, et offre plusieurs fonctionnalités pour s'adapter à différents environnements.


Fonctionnalités Principales

Vérification et installation de Python 3 : Si Python 3 n'est pas installé, le script l'installe automatiquement avant de continuer.
Vérification des prérequis : Le script vérifie et installe automatiquement les paquets nécessaires pour Postfix.
Support multi-distribution : Le script détecte la distribution Linux (Debian/Ubuntu ou CentOS/Red Hat) et ajuste les commandes en conséquence.
Validation des entrées utilisateur : Le script valide le nom d'hôte et les autres informations saisies par l'utilisateur.
Sauvegarde des fichiers de configuration : Avant de modifier les fichiers critiques, une sauvegarde est automatiquement créée.
Génération automatique des enregistrements DKIM : Le script génère la clé publique DKIM et l'inclut directement dans le rapport final.
Mode verbeux : Option pour afficher plus de détails sur les étapes du script.
Options de ligne de commande : Vous pouvez spécifier certaines options à l'avance pour un fonctionnement plus automatisé.


Prérequis

Avant de commencer, assurez-vous d'avoir :

Un serveur Linux : Le script est compatible avec Ubuntu, Debian, CentOS, et Red Hat.
Accès root ou des privilèges sudo sur le serveur.
Un nom de domaine que vous pouvez configurer pour envoyer des emails (par exemple, votre-domaine.com).


Installation

1. Télécharger le Script
Téléchargez le script setup_postfix_complete.py sur votre serveur.

bash
Copier le code
wget <lien-vers-le-script> -O setup_postfix_complete.py
2. Donner les Droits d'Exécution
Assurez-vous que le script est exécutable :

bash
Copier le code
chmod +x setup_postfix_complete.py
3. Exécuter le Script
Pour lancer le script, utilisez la commande suivante :

bash
Copier le code
sudo python3 setup_postfix_complete.py
Options de Ligne de Commande
Vous pouvez passer des options lors de l'exécution du script pour automatiser certaines entrées :

--hostname : Spécifiez le nom d'hôte du serveur de messagerie. Par exemple :

bash
Copier le code
sudo python3 setup_postfix_complete.py --hostname mail.votre-domaine.com
--external-domain : Indiquez si le domaine est géré par un fournisseur externe (oui ou non). Par exemple :

bash
Copier le code
sudo python3 setup_postfix_complete.py --external-domain oui
--verbose : Activez le mode verbeux pour voir plus de détails sur chaque étape :

bash
Copier le code
sudo python3 setup_postfix_complete.py --verbose
4. Suivre la Configuration
Le script génère un fichier de log en temps réel. Vous pouvez suivre l'exécution du script ici : /tmp/postfix_setup_log.txt.

5. Rapport Final
Une fois la configuration terminée, le script génère un rapport contenant les informations essentielles,
y compris les enregistrements DNS nécessaires pour SPF, DKIM, et DMARC. Ce rapport est sauvegardé ici : /tmp/postfix_setup_report.txt.

7. Configuration des Enregistrements DNS
Si votre domaine est géré par un fournisseur externe, ajoutez les enregistrements SPF, DKIM, et DMARC fournis dans le rapport à la configuration DNS de votre domaine.

8. Vérification du Fonctionnement
Pour vérifier que tout fonctionne correctement, vous pouvez consulter les logs de Postfix :

bash
Copier le code
tail -f /var/log/mail.log
Questions Fréquentes (FAQ)
Que faire si je rencontre une erreur ?
Consultez le fichier de log pour plus de détails. Si l'erreur persiste, vous pouvez chercher de l'aide en ligne ou demander à un administrateur système.
Comment personnaliser davantage la configuration ?
Après l'exécution du script, vous pouvez modifier le fichier /etc/postfix/main.cf pour personnaliser la configuration de Postfix.
Comment savoir si mon serveur est bien configuré ?
Vous pouvez envoyer un email de test et utiliser des services en ligne comme Mail-tester.com pour vérifier que vos emails sont correctement configurés et ne tombent pas dans les spams.


Conclusion

Ce script vous permet de configurer un serveur de messagerie Postfix de manière automatique et sécurisée, 
même si vous êtes débutant. En suivant ces instructions, vous pouvez rapidement mettre en place un serveur fonctionnel. 
N'hésitez pas à personnaliser le script selon vos besoins et à consulter le rapport final pour vous assurer que tout est correctement configuré.
