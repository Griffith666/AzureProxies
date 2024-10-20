#!/bin/bash

# Variables de configuration
RESOURCE_GROUP="<RG-Proxies>"
LOCATION="eastus"
VM_SIZE="Standard_B1s"
IMAGE="Canonical:UbuntuServer:18.04-LTS:latest"
STORAGE_ACCOUNT="<storageproxiesname>" # Must be lowercase
CONTAINER_NAME="scripts"
PROXY_PORT_BASE=30000
FRONTEND_VM="haproxy-vm"  # VM frontale pour HAProxy

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
SAS_TOKEN=$(az storage blob generate-sas \
    --account-name "$STORAGE_ACCOUNT" \
    --container-name "$CONTAINER_NAME" \
    --name "configure-proxy.sh" \
    --permissions r \
    --expiry "$(date -u -d '1 day' '+%Y-%m-%dT%H:%MZ')" \
    --output tsv)

echo "Token SAS : "$SAS_TOKEN

# URL du script avec SAS Token
SCRIPT_URL="https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/configure-proxy.sh?$SAS_TOKEN"

cat <<EOF > configure-proxy.sh
#!/bin/bash
# Configuration du serveur proxy
sudo apt update && sudo apt upgrade -y && sudo apt install -y squid apache2-utils
sudo htpasswd -bc /etc/squid/squid_passwd $PROXY_USERNAME $PROXY_PASSWORD

# Configurer Squid avec authentification
sudo tee /etc/squid/squid.conf <<EOL
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/squid_passwd
auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off

acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all

# Spécifier l'écoute sur le port spécifié
http_port \$1

# Logs
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
EOL

sudo systemctl restart squid
EOF

# Charger le script dans le Blob Storage
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "configure-proxy.sh" --file "configure-proxy.sh" --auth-mode login

# Vérifier si HAProxy existe
EXISTING_HAPROXY=$(az vm show --name "$FRONTEND_VM" --resource-group "$RESOURCE_GROUP" --query "name" --output tsv 2>/dev/null)

# Liste des backends existants pour HAProxy
HAPROXY_BACKENDS=""
HAPROXY_FRONTENDS=""

# Ajouter les machines existantes à HAProxy
EXISTING_VMS=$(az vm list --resource-group "$RESOURCE_GROUP" --query "[].name" --output tsv)
for VM in $EXISTING_VMS; do
    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM" --show-details --query publicIps --output tsv)
    PORT=$(echo "$VM" | grep -o -E '[0-9]+$')
    HAPROXY_BACKENDS+="  server $VM $IP:3128 check\n"
    HAPROXY_FRONTENDS+="  use_backend $VM if { hdr_beg(host) -i $ENTRYPOINT:$PORT }\n"
done

# Générer la configuration de HAProxy avec les nouvelles machines
for ((i=0; i<MACHINE_COUNT; i++)); do
    PROXY_PORT=$((PROXY_PORT_BASE + i))
    VM_NAME="proxy-vm-$PROXY_PORT"
    
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
  - echo "Downloading configuration script for $VM_NAME..."
  -  curl -o /tmp/configure-proxy.sh "$SCRIPT_URL"
  - echo "Script successfully downloaded, starting proxy configuration for $VM_NAME..."
  - chmod +x /tmp/configure-proxy.sh
  - /tmp/configure-proxy.sh $PROXY_PORT $PROXY_USERNAME $PROXY_PASSWORD
  - echo "Proxy successfully configured for $VM_NAME."
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

    # Ajouter la nouvelle machine à HAProxy
    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query publicIps --output tsv)
    HAPROXY_BACKENDS+="  server $VM_NAME $IP:3128 check\n"
    HAPROXY_FRONTENDS+="  use_backend $VM_NAME if { hdr_beg(host) -i $ENTRYPOINT:$PROXY_PORT }\n"
done

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

# Générer la configuration HAProxy
cat <<EOF > cloud-init-haproxy.yaml
#cloud-config
packages:
  - haproxy  # Installer HAProxy

package_update: true
package_upgrade: true

runcmd:
  - echo "Updating system..."
  - sudo apt-get update && sudo apt-get upgrade -y

  - echo "HAProxy configuration..."
  - sudo tee /etc/haproxy/haproxy.cfg <<EOL
defaults
  mode tcp
  timeout connect 5000ms
  timeout client  50000ms
  timeout server  50000ms

frontend http-in
  bind *:80
$HAPROXY_FRONTENDS

backend proxy-backends
$HAPROXY_BACKENDS
EOL

  - echo "Restarting HAProxy to apply modifications..."
  - sudo systemctl restart haproxy

  - echo "HAProxy successfully started."
EOF

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
