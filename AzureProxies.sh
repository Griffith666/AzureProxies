#!/bin/bash

# Variables de configuration
RESOURCE_GROUP="RG-Proxies"
LOCATION="eastus"
VM_SIZE="Standard_B1s"
IMAGE="Canonical:UbuntuServer:18.04-LTS:latest"
STORAGE_ACCOUNT="storageproxies"
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
    --permissions lr \
    --expiry "$(date -u -d '1 day' '+%Y-%m-%dT%H:%MZ')" \
    --output tsv)

echo "SAS Token généré pour le script de configuration du proxy : $SAS_TOKEN"

# URL du script avec SAS Token
SCRIPT_URL="https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/configure-proxy.sh?$SAS_TOKEN"



cat <<EOF > configure-proxy.sh
#!/bin/bash
# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Charger les variables de configuration
source /tmp/proxy-vars.sh

log "Configuration de Squid pour VM: $VM_NAME"
log "Port: $PROXY_PORT, Username: $PROXY_USERNAME"

# Installation des paquets nécessaires
sudo apt update
sudo apt install -y squid apache2-utils

# Nettoyer les fichiers existants de Squid
log "Nettoyage des fichiers Squid existants..."
sudo systemctl stop squid
sudo rm -rf /var/run/squid.pid
sudo rm -rf /var/spool/squid/*
sudo rm -rf /var/log/squid/*

# Créer les répertoires nécessaires avec les bonnes permissions
sudo mkdir -p /var/log/squid
sudo mkdir -p /var/spool/squid
sudo chown -R proxy:proxy /var/log/squid
sudo chown -R proxy:proxy /var/spool/squid
sudo chmod -R 755 /var/log/squid
sudo chmod -R 755 /var/spool/squid

# Configurer l'authentification
log "Configuration de l'authentification..."
sudo htpasswd -bc /etc/squid/squid_passwd "$PROXY_USERNAME" "$PROXY_PASSWORD"

# Créer la configuration Squid
log "Création de la configuration Squid..."
sudo tee /etc/squid/squid.conf <<EOL
# Paramètres d'authentification
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/squid_passwd
auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off

# ACLs
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl authenticated proxy_auth REQUIRED

# Règles d'accès
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow authenticated
http_access deny all

# Configuration du port
http_port 3128

# Configuration des logs
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log

# Configuration du cache
cache_dir ufs /var/spool/squid 100 16 256
coredump_dir /var/spool/squid
EOL

# Initialiser le cache
log "Initialisation du cache Squid..."
sudo squid -z

# Démarrer Squid
log "Démarrage de Squid..."
sudo systemctl enable squid
sudo systemctl restart squid

# Vérifier le statut
if sudo systemctl is-active --quiet squid; then
    log "Squid configuré et démarré avec succès sur le port 3128"
else
    log "Erreur lors du démarrage de Squid"
    sudo systemctl status squid
    exit 1
fi
EOF

# Charger le script dans le Blob Storage
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "configure-proxy.sh" --file "configure-proxy.sh" --auth-mode login

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
        done
}

# Vérifier si HAProxy existe et si le NSG est attaché
EXISTING_HAPROXY=$(az vm show --name "$FRONTEND_VM" --resource-group "$RESOURCE_GROUP" --query "name" --output tsv 2>/dev/null)

# Liste des backends existants pour HAProxy
HAPROXY_BACKENDS=""
HAPROXY_FRONTENDS=""

# Ajouter les machines existantes à HAProxy
EXISTING_VMS=$(az vm list --resource-group "$RESOURCE_GROUP" --query "[].name" --output tsv)
for VM in $EXISTING_VMS; do
    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM" --show-details --query publicIps --output tsv)
    PORT=$(echo "$VM" | grep -o -E '[0-9]+$')
    if [[ $VM == proxy-vm-* ]]; then
        HAPROXY_BACKENDS+="$VM $IP:3128"
        HAPROXY_FRONTENDS+="$VM $PORT"
    fi
done

# Générer la configuration de HAProxy avec les nouvelles machines
for ((i=0; i<MACHINE_COUNT; i++)); do
    PROXY_PORT=$((PROXY_PORT_BASE + i))
    VM_NAME="proxy-vm-$PROXY_PORT"


    cat <<EOF > proxy-vars-$VM_NAME.sh
VM_NAME="$VM_NAME"
PROXY_PORT="$PROXY_PORT"
PROXY_USERNAME="$PROXY_USERNAME"
PROXY_PASSWORD="$PROXY_PASSWORD"
EOF

  # Charger le fichier de variables dans le stockage Azure
    az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "proxy-vars-$VM_NAME.sh" --file "proxy-vars-$VM_NAME.sh" --auth-mode login

    # Générer le cloud-init pour chaque VM proxy
    cat <<EOF > cloud-init-$VM_NAME.yaml
#cloud-config
hostname: $VM_NAME
users:
  - name: $PROXY_USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
    ssh_authorized_keys:
      - $SSH_PUBLIC_KEY

package_update: true
package_upgrade: true

runcmd:
  - echo "Downloading script for $VM_NAME..."
  - curl -o /tmp/configure-proxy.sh "$SCRIPT_URL"
  - curl -o /tmp/proxy-vars.sh "https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/proxy-vars-$VM_NAME.sh?$SAS_TOKEN"
  - chmod +x /tmp/configure-proxy.sh /tmp/proxy-vars.sh
  - |
    source /tmp/proxy-vars.sh
    /tmp/configure-proxy.sh
EOF

    # Créer la VM avec cloud-init
    az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --image "$IMAGE" \
        --size "$VM_SIZE" \
        --custom-data cloud-init-$VM_NAME.yaml \
        --admin-username "$PROXY_USERNAME" \
        --admin-password "$PROXY_PASSWORD" \
        --only-show-errors


    # Créer et configurer le NSG pour cette machine proxy
    create_proxy_nsg "$VM_NAME"

    # Ajouter la nouvelle machine à HAProxy
    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query publicIps --output tsv)
    HAPROXY_BACKENDS+="$VM_NAME $IP:3128"
    HAPROXY_FRONTENDS+="$VM_NAME $PROXY_PORT"
done

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
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "haproxy-vars.sh" --file "haproxy-vars.sh" --auth-mode login

# Générer le cloud-init pour HAProxy
cat <<EOF > cloud-init-haproxy.yaml
#cloud-config
write_files:
  - path: /tmp/haproxy_frontends.txt
    content: |
      ${HAPROXY_FRONTENDS}
    permissions: '0644'
  - path: /tmp/haproxy_backends.txt
    content: |
      ${HAPROXY_BACKENDS}
    permissions: '0644'
  - path: /tmp/haproxy-vars.sh
    content: |
      export HAPROXY_FRONTENDS_FILE="/tmp/haproxy_frontends.txt"
      export HAPROXY_BACKENDS_FILE="/tmp/haproxy_backends.txt"
    permissions: '0644'

package_update: true
package_upgrade: true
packages:
  - haproxy
  - curl

runcmd:
  - chmod +x /tmp/haproxy-vars.sh
  - source /tmp/haproxy-vars.sh
  - curl -o /tmp/configure-haproxy.sh "${SCRIPT_URL_HAPROXY}"
  - chmod +x /tmp/configure-haproxy.sh
  - /tmp/configure-haproxy.sh
  - systemctl enable haproxy
  - systemctl restart haproxy
EOF

cat <<EOF > configure-haproxy.sh
#!/bin/bash

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Démarrage de la configuration HAProxy"

# Vérifier les fichiers
if [ ! -f "/tmp/haproxy_frontends.txt" ] || [ ! -f "/tmp/haproxy_backends.txt" ]; then
    log "Erreur: Fichiers de configuration manquants"
    exit 1
fi

# Lire le contenu des fichiers
HAPROXY_FRONTENDS=$(cat "/tmp/haproxy_frontends.txt" | sed 's/\\n//g')
HAPROXY_BACKENDS=$(cat "/tmp/haproxy_backends.txt" | sed 's/\\n//g')

# Extraire les paires port/backend uniques
BACKEND_PORTS=$(echo "$HAPROXY_FRONTENDS" | grep -o 'proxy.privato.app:[0-9]*' | cut -d':' -f2 | sort -u)

# Créer la configuration HAProxy
log "Création de la configuration HAProxy..."
sudo tee /etc/haproxy/haproxy.cfg <<EOL
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

# Frontend pour chaque port
$(for port in $BACKEND_PORTS; do
    vm_name=$(echo "$HAPROXY_FRONTENDS" | grep ":$port" | grep -o 'proxy-vm-[0-9]*')
    server_line=$(echo "$HAPROXY_BACKENDS" | grep "server $vm_name")
    if [ ! -z "$vm_name" ] && [ ! -z "$server_line" ]; then
        echo "frontend ft_$port"
        echo "    bind *:$port"
        echo "    mode tcp"
        echo "    default_backend bk_$port"
        echo ""
        echo "backend bk_$port"
        echo "    mode tcp"
        echo "    server $server_line"
        echo ""
    fi
done)

# Statistics page
frontend stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST
EOL

# Vérifier la configuration
log "Vérification de la configuration HAProxy..."
if sudo haproxy -c -f /etc/haproxy/haproxy.cfg; then
    log "Configuration valide"
    sudo systemctl restart haproxy
    log "HAProxy redémarré avec succès"
else
    log "Erreur dans la configuration HAProxy"
    exit 1
fi
EOF

az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "configure-haproxy.sh" --file "configure-haproxy.sh" --auth-mode login


# Créer ou mettre à jour la machine HAProxy
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
    echo "Mise à jour de la configuration de HAProxy..."
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

# Haproxy status
echo "Vérification de l'état de HAProxy..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$FRONTEND_VM" \
  --command-id RunShellScript \
  --scripts "systemctl status haproxy"