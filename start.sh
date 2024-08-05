def install_packages(packages):
    for package in packages:
        install_package(package)

def configure_postfix_tls():
    tls_settings = {
        'smtpd_tls_cert_file': '/etc/ssl/certs/ssl-cert-snakeoil.pem',
        'smtpd_tls_key_file': '/etc/ssl/private/ssl-cert-snakeoil.key',
        'smtpd_use_tls': 'yes',
        'smtpd_tls_auth_only': 'yes',
        'smtp_tls_security_level': 'may',
        'smtpd_tls_received_header': 'yes',
        'smtp_tls_note_starttls_offer': 'yes',
        'smtpd_tls_session_cache_database': 'btree:${data_directory}/smtpd_scache',
        'smtp_tls_session_cache_database': 'btree:${data_directory}/smtp_scache',
        'tls_random_source': 'dev:/dev/urandom',
        'smtpd_tls_loglevel': '1',
    }
    for key, value in tls_settings.items():
        execute_command(f"postconf -e '{key} = {value}'", f"Failed to set {key}.")

def configure_postfix_restrictions():
    restrictions = {
        'smtpd_relay_restrictions': 'permit_mynetworks permit_sasl_authenticated defer_unauth_destination',
        'smtpd_recipient_restrictions': 'permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination',
    }
    for key, value in restrictions.items():
        execute_command(f"postconf -e '{key} = {value}'", f"Failed to set {key}.")

# Appel des nouvelles fonctions dans la fonction configure_postfix
def configure_postfix(hostname, email):
    logging.info("Configuring Postfix...")
    execute_command(f"postconf -e 'myhostname = {hostname}'", "Failed to set hostname in Postfix.")
    configure_postfix_tls()
    configure_postfix_restrictions()
    # ... Reste du code inchangé
