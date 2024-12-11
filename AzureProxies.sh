#!/bin/bash
set -e

# Variables de configuration
RESOURCE_GROUP="RG-Leo"
LOCATION="eastus"
VM_SIZE="Standard_B2s"
IMAGE="Canonical:UbuntuServer:18.04-LTS:latest"
STORAGE_ACCOUNT="storageproxiesleo"
CONTAINER_NAME="scripts"
PROXY_PORT_BASE=30000
FRONTEND_VM="haproxy-vm"  # VM frontale pour HAProxy
NSG_NAME="haproxy-nsg"    # Nom du NSG lié à la VM HAProxy

# Vérifier l'existence du groupe de ressources, sinon le créer
if ! az group exists --name "$RESOURCE_GROUP"; then
    echo "Le groupe de ressources $RESOURCE_GROUP n'existe pas, création en cours..."
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
else
    echo "Le groupe de ressources $RESOURCE_GROUP existe déjà."
fi

# Demander le nombre de machines à créer
read -p "Combien de machines souhaitez-vous créer ? " MACHINE_COUNT

# Demander l'utilisateur et le mot de passe pour les proxies et SSH
read -p "Nom d'utilisateur des proxies (et SSH) : " PROXY_USERNAME
read -sp "Mot de passe des proxies (et SSH) : " PROXY_PASSWORD
echo

# Demander le nom de domaine pour l'entrypoint
read -p "Nom de domaine pour l'entrypoint (laisser vide pour utiliser l'IP publique) : " ENTRYPOINT

# Demander la clé publique SSH à l'utilisateur
read -p "Veuillez fournir la clé publique SSH : " SSH_PUBLIC_KEY

# Vérifier si le compte de stockage existe dans le groupe de ressources
EXISTING_STORAGE_ACCOUNT=$(az storage account show --name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" --query "name" --output tsv 2>/dev/null)

# Créer le compte de stockage si non existant
if [[ -z "$EXISTING_STORAGE_ACCOUNT" ]]; then
    echo "Le compte de stockage $STORAGE_ACCOUNT n'existe pas dans le groupe de ressources $RESOURCE_GROUP, création en cours..."
    az storage account create --name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" --location "$LOCATION" --sku Standard_LRS --only-show-errors
else
    echo "Le compte de stockage $STORAGE_ACCOUNT existe déjà dans le groupe de ressources $RESOURCE_GROUP."
fi

# Obtenir la clé du compte de stockage
STORAGE_KEY=$(az storage account keys list --resource-group "$RESOURCE_GROUP" --account-name "$STORAGE_ACCOUNT" --query "[0].value" --output tsv)

# Créer le conteneur Blob s'il n'existe pas
az storage container create --name "$CONTAINER_NAME" --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --only-show-errors

# Générer un SAS Token valide pour le fichier de configuration du proxy
SAS_TOKEN=$(az storage container generate-sas \
    --account-name "$STORAGE_ACCOUNT" \
    --name "$CONTAINER_NAME" \
    --permissions racwdl \
    --expiry "$(date -u -d '1 day' '+%Y-%m-%dT%H:%MZ')" \
    --https-only \
    --output tsv)

echo "SAS Token généré pour le script de configuration du proxy : $SAS_TOKEN"

# URL du script avec SAS Token
SCRIPT_URL="https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/configure-proxy.sh?$SAS_TOKEN"


cat <<'EOF' > configure-proxy.sh
#!/bin/bash
set -e

# Configuration du logging
exec 1> >(tee -a /var/log/squid-setup.log) 2>&1

# Fonction de logging
log() {
    local level=$1
    local message=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a /var/log/squid-setup.log
    logger -t squid-setup "$level: $message"
}

# Fonction de vérification des erreurs
check_error() {
    local exit_code=$1
    local step=$2
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Échec à l'étape : $step (code: $exit_code)"
        log "ERROR" "Contenu de /var/log/squid-setup.log :"
        tail -n 50 /var/log/squid-setup.log
        exit $exit_code
    else
        log "INFO" "Succès de l'étape : $step"
    fi
}

# Configuration TPROXY
setup_tproxy() {
    log "INFO" "Configuration de TPROXY..."
    
    # Activation des modules
    modprobe iptable_mangle
    modprobe nf_tproxy_ipv4
    modprobe nf_socket_ipv4
    
    # Configuration du chargement automatique
    cat > /etc/modules-load.d/tproxy.conf <<EOL
iptable_mangle
nf_tproxy_ipv4
nf_socket_ipv4
EOL

    # Configuration sysctl
    cat > /etc/sysctl.d/10-tproxy.conf <<EOL
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
EOL

    sysctl -p /etc/sysctl.d/10-tproxy.conf

    # Configuration iptables
    iptables -t mangle -N DIVERT || true
    iptables -t mangle -F DIVERT
    iptables -t mangle -A DIVERT -j MARK --set-mark 1
    iptables -t mangle -A DIVERT -j ACCEPT

    # Configuration du routage transparent
    iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 3128
    iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 3129

    # Pré-configuration de iptables-persistent pour éviter l'interaction
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Sauvegarde des règles
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4

    return 0
}

# Configuration des répertoires SSL
setup_ssl_directories() {
    log "INFO" "Configuration des répertoires SSL..."
    
    # Nettoyage
    rm -rf /var/lib/squid/ssl_db
    rm -rf /var/cache/squid/*
    
    # Création structure
    install -d -m 755 /var/lib/squid
    chown proxy:proxy /var/lib/squid
    
    return 0
}

# Initialisation SSL
initialize_ssl_db() {
    log "INFO" "Initialisation SSL..."
    
    if [ ! -x "/usr/lib/squid/security_file_certgen" ]; then
        log "ERROR" "security_file_certgen non trouvé ou non exécutable"
        return 1
    fi

    if [ ! -d "/var/lib/squid" ]; then
        log "ERROR" "Répertoire /var/lib/squid manquant"
        return 1
    fi
    
    rm -rf /var/lib/squid/ssl_db/*
    su -s /bin/bash proxy -c "/usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB"
    
    if [ ! -d "/var/lib/squid/ssl_db" ]; then
        log "ERROR" "Échec de création du répertoire ssl_db"
        return 1
    fi
    
    return 0
}

setup_ssl_certificates() {
    log "INFO" "Configuration des certificats SSL..."
    
    # Création du répertoire SSL
    mkdir -p /etc/squid/ssl
    cd /etc/squid/ssl
    
    # Génération du certificat CA
    openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
        -extensions v3_ca \
        -keyout squid-ca-key.pem \
        -out squid-ca-cert.pem \
        -subj "/C=FR/ST=Paris/L=Paris/O=ProxyAuth CA/CN=Proxy CA"
    
    # Génération du certificat serveur
    openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout squid.key \
        -out squid.csr \
        -subj "/C=FR/ST=Paris/L=Paris/O=ProxyAuth/CN=$VM_NAME"
    
    # Signature du certificat serveur
    openssl x509 -req -days 3650 -in squid.csr \
        -CA squid-ca-cert.pem \
        -CAkey squid-ca-key.pem \
        -CAcreateserial \
        -out squid.crt
    
    # Création du fichier PEM combiné
    cat squid.key squid.crt > squid.pem
    
    # Configuration des permissions
    chmod 400 squid*.pem squid.key
    chown proxy:proxy squid*.pem squid.key
    
    return 0
}

# DÉBUT EXÉCUTION PRINCIPALE
log "INFO" "Début installation Squid"

# Vérification variables
if [ ! -f /tmp/proxy-vars.sh ]; then
    log "ERROR" "Fichier de variables non trouvé"
    exit 1
fi

source /tmp/proxy-vars.sh
check_required_vars

# Configuration TPROXY
if ! setup_tproxy; then
    log "ERROR" "Échec configuration TPROXY"
    exit 1
fi

# Installation paquets
PACKAGES=(
    "build-essential"
    "openssl"
    "libssl-dev"
    "pkg-config"
    "apache2-utils"
    "ssl-cert"
    "libldap2-dev"
    "libsasl2-dev"
    "libxml2-dev"
    "libpcre3-dev"
    "libkrb5-dev"
    "nettle-dev"
    "libnetfilter-conntrack-dev"
    "libpam0g-dev"
    "libdb-dev"
    "libexpat1-dev"
    "libcdb-dev"
    "libcap-dev"
    "libecap3-dev"
    "libsystemd-dev"
    "iptables-persistent"
)

apt-get update
for package in "${PACKAGES[@]}"; do
    apt-get install -y $package
    check_error $? "Installation $package"
done

# Compilation Squid
cd /tmp
wget http://www.squid-cache.org/Versions/v5/squid-5.9.tar.gz
tar xzf squid-5.9.tar.gz
cd squid-5.9

./configure \
    --prefix=/usr \
    --localstatedir=/var \
    --libexecdir=/usr/lib/squid \
    --datadir=/usr/share/squid \
    --sysconfdir=/etc/squid \
    --with-default-user=proxy \
    --with-logdir=/var/log/squid \
    --with-pidfile=/var/run/squid.pid \
    --with-openssl \
    --enable-ssl-crtd \
    --enable-linux-netfilter \
    --with-nat-devpoll \
    --enable-ssl \
    --enable-auth-basic="NCSA"

make -j$(nproc)
check_error $? "Compilation"

make install
check_error $? "Installation"

# Configuration répertoires
for dir in /etc/squid /var/log/squid /var/spool/squid /var/cache/squid /usr/lib/squid /usr/share/squid/errors; do
    install -d -m 750 "$dir"
    chown proxy:proxy "$dir"
done

# Installation security_file_certgen
security_certgen=$(find . -name "security_file_certgen" -type f)
if [ -n "$security_certgen" ]; then
    install -m 755 "$security_certgen" /usr/lib/squid/security_file_certgen
    chown root:proxy /usr/lib/squid/security_file_certgen
else
    log "ERROR" "security_file_certgen non trouvé"
    exit 1
fi

# Configuration SSL
log "INFO" "Configuration SSL..."
if ! setup_ssl_directories; then
    log "ERROR" "Échec configuration répertoires SSL"
    exit 1
fi

if ! initialize_ssl_db; then
    log "ERROR" "Échec initialisation SSL"
    exit 1
fi

# Configuration Squid
cat > /etc/squid/squid.conf <<EOL
# Ports d'écoute
http_port 3128 intercept
https_port 3129 intercept ssl-bump \
    cert=/etc/squid/ssl/squid.pem \
    generate-host-certificates=on \
    dynamic_cert_mem_cache_size=4MB

# ACLs de base
acl localnet src all
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 1025-65535
acl CONNECT method CONNECT

# Règles d'accès
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
http_access deny all

# Configuration SSL Bump
ssl_bump server-first all
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
sslcrtd_children 5

# Configuration TLS
tls_outgoing_options options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1 cipher=HIGH:MEDIUM:!RC4:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS

# Configuration du cache
cache_dir ufs /var/spool/squid 100 16 256
coredump_dir /var/spool/squid

# Patterns de rafraîchissement
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
EOL

# Initialisation cache
if ! su -s /bin/bash proxy -c "/usr/sbin/squid -z"; then
    log "ERROR" "Échec initialisation cache"
    exit 1
fi

if ! setup_ssl_certificates; then
    log "ERROR" "Échec de la configuration des certificats SSL"
    exit 1
fi

# Service systemd
cat > /etc/systemd/system/squid.service <<EOL
[Unit]
Description=Squid proxy server
After=network.target

[Service]
Type=forking
PIDFile=/run/squid.pid
ExecStartPre=/usr/sbin/squid -N -z
ExecStart=/usr/sbin/squid -sYC
ExecReload=/usr/sbin/squid -k reconfigure
ExecStop=/usr/sbin/squid -k shutdown
Restart=always

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable squid
systemctl start squid

# Vérifications finales
sleep 10
if ! systemctl is-active --quiet squid; then
    log "ERROR" "Squid non démarré"
    systemctl status squid
    exit 1
fi

if ! netstat -tulpn | grep -q ":3128"; then
    log "ERROR" "Port 3128 non ouvert"
    exit 1
fi

log "INFO" "Installation Squid terminée avec succès"
EOF

# Charger le script dans le Blob Storage
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "configure-proxy.sh" --file "configure-proxy.sh" --auth-mode login --overwrite

# Fonction pour créer le NSG et associer les règles de sécurité
create_nsg_haproxy() {
    # Vérifier si le NSG existe déjà
    EXISTING_NSG=$(az network nsg show --name "$NSG_NAME" --resource-group "$RESOURCE_GROUP" --query "name" --output tsv 2>/dev/null)
    if [[ -z "$EXISTING_NSG" ]]; then
        echo "Le NSG $NSG_NAME n'existe pas, création en cours..."
        az network nsg create --name "$NSG_NAME" --resource-group "$RESOURCE_GROUP" --location "$LOCATION"
    else
        echo "Le NSG $NSG_NAME existe déjà."
    fi
    # Attacher le NSG à l'interface réseau de la VM HAProxy
    NIC_ID=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$FRONTEND_VM" --query "networkProfile.networkInterfaces[0].id" --output tsv)
    if [[ -n "$NIC_ID" ]]; then
        echo "Association du NSG $NSG_NAME à la NIC $NIC_ID de HAProxy..."
        az network nic update --ids "$NIC_ID" --network-security-group "$NSG_NAME"
    fi
}

create_proxy_nsg() {
    local VM_NAME=$1
    local NSG_NAME="${VM_NAME}-nsg"
    
    echo "Configuration du NSG pour $VM_NAME..."
    
    # Créer le NSG pour la machine proxy
    az network nsg create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$NSG_NAME" \
        --location "$LOCATION"
    
    # Ajouter règle pour SSH
    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG_NAME" \
        --name "Allow-SSH" \
        --priority 1000 \
        --destination-port-ranges 22 \
        --protocol Tcp \
        --access Allow \
        --direction Inbound
    
    # Ajouter règle pour Squid
    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG_NAME" \
        --name "Allow-Squid" \
        --priority 1001 \
        --destination-port-ranges 3128 \
        --protocol Tcp \
        --access Allow \
        --direction Inbound
    
    # Obtenir l'ID de la carte réseau de la VM
    local NIC_ID=$(az vm show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --query "networkProfile.networkInterfaces[0].id" \
        --output tsv)
    
    # Associer le NSG à la carte réseau
    if [[ -n "$NIC_ID" ]]; then
        echo "Association du NSG $NSG_NAME à la carte réseau de $VM_NAME..."
        az network nic update \
            --ids "$NIC_ID" \
            --network-security-group "$NSG_NAME"
    fi
}

# Fonction pour mettre à jour le NSG de HAProxy avec les ports des machines proxy
update_nsg_haproxy() {
    create_nsg_haproxy
    for ((i=0; i<MACHINE_COUNT; i++)); do
        PROXY_PORT=$((PROXY_PORT_BASE + i))
        echo "Ajout de la règle pour ouvrir le port $PROXY_PORT dans le NSG $NSG_NAME"
        az network nsg rule create \
            --resource-group "$RESOURCE_GROUP" \
            --nsg-name "$NSG_NAME" \
            --name "Allow-Proxy-Port-$PROXY_PORT" \
            --priority $((200 + i)) \
            --destination-port-ranges "$PROXY_PORT" \
            --protocol Tcp \
            --access Allow \
            --direction Inbound
        
        # Ajouter règle pour SSH
        az network nsg rule create \
            --resource-group "$RESOURCE_GROUP" \
            --nsg-name "$NSG_NAME" \
            --name "Allow-SSH" \
            --priority 1002 \
            --destination-port-ranges 22 \
            --protocol Tcp \
            --access Allow \
            --direction Inbound
        done
}

# Script de mise à jour de la configuration HAProxy
cat <<'EOF' > update_haproxy.sh
#!/bin/bash

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Début de la mise à jour de la configuration HAProxy"

# Vérifier l'existence des fichiers de configuration
if [ ! -f "/tmp/haproxy_frontends.txt" ] || [ ! -f "/tmp/haproxy_backends.txt" ]; then
    log "Erreur: Fichiers de configuration manquants"
    exit 1
fi

# Créer la nouvelle configuration HAProxy
log "Création de la nouvelle configuration HAProxy..."
cat > /etc/haproxy/haproxy.cfg << 'EOL'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode tcp
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms

EOL

# Initialiser les compteurs
frontend_count=0
backend_count=0

# Traiter chaque ligne du fichier frontends
while read line; do
    if [ -z "$line" ]; then
        continue
    fi
    
    # Extraire IP et port
    ip=$(echo $line | cut -d' ' -f1)
    port=$(echo $line | cut -d' ' -f2)
    
    log "Mise à jour du frontend pour IP: $ip, Port: $port"
    
    # Vérifier que le port est un nombre
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log "Erreur: Port invalide '$port' pour l'IP $ip"
        continue
    fi

    # Configurer le frontend
    cat >> /etc/haproxy/haproxy.cfg << EOL
frontend ft_${port}
    bind *:${port}
    mode tcp
    default_backend bk_${port}

EOL
    frontend_count=$((frontend_count + 1))

    # Rechercher le backend correspondant
    vm_name="proxy-vm-${port}"
    backend_line=$(grep "^$vm_name" /tmp/haproxy_backends.txt || echo "")

    if [ -n "$backend_line" ]; then
        # Extraire l'IP:port du backend
        backend_ip_port=$(echo "$backend_line" | cut -d' ' -f2)
        
        # Configurer le backend
        cat >> /etc/haproxy/haproxy.cfg << EOL
backend bk_${port}
    mode tcp
    server ${vm_name} ${backend_ip_port} check

EOL
        backend_count=$((backend_count + 1))
        log "Backend mis à jour pour ${vm_name} avec ${backend_ip_port}"
    else
        log "Attention: Aucun backend trouvé pour le port ${port}"
    fi
done < /tmp/haproxy_frontends.txt

# Vérifier qu'au moins une configuration a été créée
if [ $frontend_count -eq 0 ] || [ $backend_count -eq 0 ]; then
    log "Erreur: Aucune configuration frontend/backend valide n'a été créée"
    exit 1
fi

log "Configuration mise à jour avec $frontend_count frontends et $backend_count backends"

# Ajouter la configuration des stats
cat >> /etc/haproxy/haproxy.cfg << 'EOL'
frontend stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST
EOL

# Vérifier et appliquer la configuration
log "Vérification de la nouvelle configuration HAProxy..."
if haproxy -c -f /etc/haproxy/haproxy.cfg; then
    log "Configuration valide"
    systemctl restart haproxy
    if systemctl is-active --quiet haproxy; then
        log "HAProxy redémarré avec succès"
        log "Ports en écoute:"
        netstat -tlnp | grep haproxy
    else
        log "Erreur: HAProxy n'a pas démarré correctement"
        systemctl status haproxy
        exit 1
    fi
else
    log "Erreur dans la configuration HAProxy"
    exit 1
fi
EOF

# Charger le script dans le Blob Storage
az storage blob upload \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$STORAGE_KEY" \
    --container-name "$CONTAINER_NAME" \
    --name "update_haproxy.sh" \
    --file "update_haproxy.sh" \
    --auth-mode login \
    --overwrite

# Fonction de mise à jour de HAProxy
update_haproxy_configuration() {
    echo "Mise à jour de la configuration HAProxy..."
    
    # Créer les fichiers de configuration temporaires sur le blob storage
    echo -e "$HAPROXY_FRONTENDS" > haproxy_frontends.txt
    echo -e "$HAPROXY_BACKENDS" > haproxy_backends.txt
    
    # Upload des fichiers vers le blob storage
    az storage blob upload \
        --account-name "$STORAGE_ACCOUNT" \
        --account-key "$STORAGE_KEY" \
        --container-name "$CONTAINER_NAME" \
        --name "haproxy_frontends.txt" \
        --file "haproxy_frontends.txt" \
        --overwrite
        
    az storage blob upload \
        --account-name "$STORAGE_ACCOUNT" \
        --account-key "$STORAGE_KEY" \
        --container-name "$CONTAINER_NAME" \
        --name "haproxy_backends.txt" \
        --file "haproxy_backends.txt" \
        --overwrite

    # Construction des URLs avec SAS Token
    local frontends_url="https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/haproxy_frontends.txt?$SAS_TOKEN"
    local backends_url="https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/haproxy_backends.txt?$SAS_TOKEN"
    local script_url="https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/update_haproxy.sh?$SAS_TOKEN"

    # Commande d'exécution sur la VM avec retry
    az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP" \
        --name "$FRONTEND_VM" \
        --command-id RunShellScript \
        --scripts "
            # Fonction de téléchargement avec retry
            download_with_retry() {
                local url=\$1
                local output=\$2
                local max_attempts=5
                local attempt=1
                
                while [ \$attempt -le \$max_attempts ]; do
                    echo \"Tentative \$attempt de téléchargement de \$output\"
                    if curl -s -f -L -o \$output \"\$url\"; then
                        echo \"Téléchargement réussi de \$output\"
                        return 0
                    else
                        echo \"Échec du téléchargement (tentative \$attempt)\"
                        sleep 10
                        attempt=\$((attempt + 1))
                    fi
                done
                return 1
            }

            # Téléchargement des fichiers
            download_with_retry \"$frontends_url\" \"/tmp/haproxy_frontends.txt\" && \
            download_with_retry \"$backends_url\" \"/tmp/haproxy_backends.txt\" && \
            download_with_retry \"$script_url\" \"/tmp/update_haproxy.sh\" && \
            chmod +x /tmp/update_haproxy.sh && \
            /tmp/update_haproxy.sh
        "
}

# Liste des backends existants pour HAProxy
HAPROXY_BACKENDS=""
HAPROXY_FRONTENDS=""

# Ajouter les machines existantes à HAProxy
EXISTING_VMS=$(az vm list --resource-group "$RESOURCE_GROUP" --query "[?starts_with(name, 'proxy-vm-')].name" --output tsv)
for VM in $EXISTING_VMS; do
    if [[ $VM == proxy-vm-* ]]; then
        IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM" --show-details --query publicIps --output tsv)
        PORT=$(echo "$VM" | grep -o -E '[0-9]+$')
        
        # Ajouter aux configurations HAProxy
        if [ -n "$IP" ] && [ -n "$PORT" ]; then
            HAPROXY_FRONTENDS="${HAPROXY_FRONTENDS}${IP} ${PORT}\n"
            HAPROXY_BACKENDS="${HAPROXY_BACKENDS}${VM} ${IP}:3128\n"
        fi
    fi
done

    cat <<EOF > proxy-vars-$VM_NAME.sh
VM_NAME="$VM_NAME"
PROXY_PORT="$PROXY_PORT"
PROXY_USERNAME="$PROXY_USERNAME"
PROXY_PASSWORD="$PROXY_PASSWORD"
EOF

  # Charger le fichier de variables dans le stockage Azure
    az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "proxy-vars-$VM_NAME.sh" --file "proxy-vars-$VM_NAME.sh" --auth-mode login --overwrite

create_cloud_init() {
    local VM_NAME=$1
    cat > "cloud-init-$VM_NAME.yaml" <<EOF
#cloud-config
package_update: true
package_upgrade: true

packages:
  - apache2-utils
  - curl
  - net-tools

write_files:
  - path: /tmp/install_proxy.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      echo "Installation des scripts de configuration..."
      SCRIPT_URL='https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER_NAME}/configure-proxy.sh?${SAS_TOKEN}'
      VARS_URL='https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER_NAME}/proxy-vars-${VM_NAME}.sh?${SAS_TOKEN}'
      
      curl -s -f -L -o /tmp/configure-proxy.sh "\$SCRIPT_URL"
      curl -s -f -L -o /tmp/proxy-vars.sh "\$VARS_URL"
      
      chmod +x /tmp/configure-proxy.sh /tmp/proxy-vars.sh

runcmd:
  - bash /tmp/install_proxy.sh
  - source /tmp/proxy-vars.sh
  - bash /tmp/configure-proxy.sh
EOF
}

# Créer les nouvelles machines et ajouter leurs configurations
for ((i=0; i<MACHINE_COUNT; i++)); do
    PROXY_PORT=$((PROXY_PORT_BASE + i))
    VM_NAME="proxy-vm-$PROXY_PORT"
    
    # Vérifier si la VM existe déjà
    if ! az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" &>/dev/null; then
        echo "Création de la nouvelle VM $VM_NAME..."
        # Créer nouvelle VM et configurer

        cat <<EOF > proxy-vars-$VM_NAME.sh
VM_NAME="$VM_NAME"
PROXY_PORT="$PROXY_PORT"
PROXY_USERNAME="$PROXY_USERNAME"
PROXY_PASSWORD="$PROXY_PASSWORD"
EOF

        # Upload vers le blob storage
        az storage blob upload \
            --account-name "$STORAGE_ACCOUNT" \
            --account-key "$STORAGE_KEY" \
            --container-name "$CONTAINER_NAME" \
            --name "proxy-vars-$VM_NAME.sh" \
            --file "proxy-vars-$VM_NAME.sh" \
            --overwrite
            
        # Créer le fichier cloud-init pour la VM
        create_cloud_init "$VM_NAME"

        # Créer la VM
        az vm create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VM_NAME" \
            --image "$IMAGE" \
            --size "$VM_SIZE" \
            --custom-data "@cloud-init-$VM_NAME.yaml" \
            --admin-username "$PROXY_USERNAME" \
            --admin-password "$PROXY_PASSWORD" \
            --only-show-errors
                
        PROXY_IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query publicIps --output tsv)
        
        if [ -n "$PROXY_IP" ]; then
            HAPROXY_FRONTENDS="${HAPROXY_FRONTENDS}${PROXY_IP} ${PROXY_PORT}\n"
            HAPROXY_BACKENDS="${HAPROXY_BACKENDS}${VM_NAME} ${PROXY_IP}:3128\n"
        fi
        
        create_proxy_nsg "$VM_NAME"
    fi
done

update_haproxy_configuration



# Générer un SAS Token valide pour le fichier de configuration du haproxy
SAS_TOKEN_HAPROXY=$(az storage container generate-sas \
    --account-name "$STORAGE_ACCOUNT" \
    --name "$CONTAINER_NAME" \
    --permissions lr \
    --expiry "$(date -u -d '1 day' '+%Y-%m-%dT%H:%MZ')" \
    --output tsv)

# Créer l'URL complète du script avec le SAS Token
SCRIPT_URL_HAPROXY="https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/configure-haproxy.sh?$SAS_TOKEN_HAPROXY"

# Message de debug pour afficher l'URL générée
echo "Script de configuration HAProxy : $SCRIPT_URL_HAPROXY"

# Création d'un fichier de variables pour HAProxy avec fichiers temporaires
cat <<'EOF' > haproxy-vars.sh
export HAPROXY_FRONTENDS_FILE="/tmp/haproxy_frontends.txt"
export HAPROXY_BACKENDS_FILE="/tmp/haproxy_backends.txt"

# Créer les fichiers avec le contenu
cat > "${HAPROXY_FRONTENDS_FILE}" <<FRONTENDS
${HAPROXY_FRONTENDS}
FRONTENDS

cat > "${HAPROXY_BACKENDS_FILE}" <<BACKENDS
${HAPROXY_BACKENDS}
BACKENDS
EOF


# Charger le fichier de variables HAProxy dans le stockage Azure
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "haproxy-vars.sh" --file "haproxy-vars.sh" --auth-mode login --overwrite

# Créer le fichier cloud-init pour HAProxy avec les configurations intégrées
cat <<EOF > cloud-init-haproxy.yaml
#cloud-config
write_files:
  - path: /tmp/haproxy_frontends.txt
    content: |
$(echo -e "$HAPROXY_FRONTENDS")
    permissions: '0644'
  - path: /tmp/haproxy_backends.txt
    content: |
$(echo -e "$HAPROXY_BACKENDS")
    permissions: '0644'

package_update: true
package_upgrade: true
packages:
  - haproxy
  - curl

runcmd:
  - echo "Downloading HAProxy configuration script..."
  - curl -o /tmp/configure-haproxy.sh "${SCRIPT_URL_HAPROXY}"
  - chmod +x /tmp/configure-haproxy.sh
  - /tmp/configure-haproxy.sh
  - systemctl enable haproxy
  - systemctl restart haproxy
EOF

cat <<'EOFSCRIPT' > configure-haproxy.sh
#!/bin/bash

# Fonction de logging avec message en paramètre
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Démarrage de la configuration HAProxy"

# Attendre que les fichiers soient disponibles
max_attempts=30
attempt=1
while [ $attempt -le $max_attempts ]; do
    if [ -f "/tmp/haproxy_frontends.txt" ] && [ -f "/tmp/haproxy_backends.txt" ]; then
        log "Fichiers de configuration trouvés"
        break
    fi
    log "Tentative $attempt/$max_attempts: Attente des fichiers de configuration..."
    sleep 10
    attempt=$((attempt + 1))
done

if [ ! -f "/tmp/haproxy_frontends.txt" ] || [ ! -f "/tmp/haproxy_backends.txt" ]; then
    log "Erreur: Fichiers de configuration non trouvés après $max_attempts tentatives"
    exit 1
fi

# Vérifier le contenu des fichiers
log "Contenu de haproxy_frontends.txt:"
cat /tmp/haproxy_frontends.txt
log "Contenu de haproxy_backends.txt:"
cat /tmp/haproxy_backends.txt

# Créer la configuration HAProxy de base
log "Création de la configuration HAProxy..."
cat > /etc/haproxy/haproxy.cfg << 'EOL'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode tcp
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms

EOL

# Initialiser les compteurs
frontend_count=0
backend_count=0

# Traiter chaque ligne du fichier frontends
while read line; do
    if [ -z "$line" ]; then
        continue
    fi
    
    # Extraire IP et port
    ip=$(echo $line | cut -d' ' -f1)
    port=$(echo $line | cut -d' ' -f2)
    
    log "Traitement du frontend pour IP: $ip, Port: $port"
    
    # Vérifier que le port est un nombre
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log "Erreur: Port invalide '$port' pour l'IP $ip"
        continue
    fi

    # Configurer le frontend
    cat >> /etc/haproxy/haproxy.cfg << EOL
frontend ft_${port}
    bind *:${port}
    mode tcp
    default_backend bk_${port}

EOL
    frontend_count=$((frontend_count + 1))

    # Rechercher le backend correspondant
    vm_name="proxy-vm-${port}"
    backend_line=$(grep "^$vm_name" /tmp/haproxy_backends.txt || echo "")

    if [ -n "$backend_line" ]; then
        # Extraire l'IP:port du backend
        backend_ip_port=$(echo "$backend_line" | cut -d' ' -f2)
        
        # Configurer le backend
        cat >> /etc/haproxy/haproxy.cfg << EOL
backend bk_${port}
    mode tcp
    server ${vm_name} ${backend_ip_port} check

EOL
        backend_count=$((backend_count + 1))
        log "Backend configuré pour ${vm_name} avec ${backend_ip_port}"
    else
        log "Attention: Aucun backend trouvé pour le port ${port}"
    fi
done < /tmp/haproxy_frontends.txt

# Vérifier qu'au moins une configuration a été créée
if [ $frontend_count -eq 0 ] || [ $backend_count -eq 0 ]; then
    log "Erreur: Aucune configuration frontend/backend valide n'a été créée"
    exit 1
fi

log "Configuration créée avec $frontend_count frontends et $backend_count backends"

# Ajouter la configuration des stats
cat >> /etc/haproxy/haproxy.cfg << 'EOL'
frontend stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST
EOL

# Vérifier et appliquer la configuration
log "Configuration HAProxy finale:"
cat /etc/haproxy/haproxy.cfg

if haproxy -c -f /etc/haproxy/haproxy.cfg; then
    log "Configuration valide"
    systemctl restart haproxy
    if systemctl is-active --quiet haproxy; then
        log "HAProxy redémarré avec succès"
        log "Ports en écoute:"
        netstat -tlnp | grep haproxy
    else
        log "Erreur: HAProxy n'a pas démarré correctement"
        systemctl status haproxy
        exit 1
    fi
else
    log "Erreur dans la configuration HAProxy"
    exit 1
fi
EOFSCRIPT

az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "configure-haproxy.sh" --file "configure-haproxy.sh" --auth-mode login --overwrite

# 4. Vérification de l'existence de la VM HAProxy avant création
EXISTING_HAPROXY=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$FRONTEND_VM" --query "name" --output tsv 2>/dev/null || echo "")

if [[ -z "$EXISTING_HAPROXY" ]]; then
    echo "Création de la machine HAProxy..."
    az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$FRONTEND_VM" \
        --image "$IMAGE" \
        --size "$VM_SIZE" \
        --admin-username "$PROXY_USERNAME" \
        --admin-password "$PROXY_PASSWORD" \
        --custom-data cloud-init-haproxy.yaml \
        --only-show-errors
else
    echo "Machine HAProxy existante, mise à jour de la configuration..."
    update_haproxy_configuration
fi

# Mettre à jour le NSG avec les nouveaux ports
update_nsg_haproxy

# Final message avec IP publique des machines créées
echo "Création des machines terminée. Voici les IPs publiques des machines créées :"

for ((i=0; i<MACHINE_COUNT; i++)); do
    VM_NAME="proxy-vm-$((PROXY_PORT_BASE + i))"
    PUBLIC_IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query [publicIps] --output tsv)
    echo "$VM_NAME : $PUBLIC_IP"
done

# IP publique du HAProxy
HA_PROXY_IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$FRONTEND_VM" --show-details --query [publicIps] --output tsv)
echo "HAProxy : $HA_PROXY_IP"
