#!/bin/bash

# Variables de configuration
RESOURCE_GROUP="<RG-Name-Here>"  # Nom du groupe de ressources
LOCATION="eastus"        # Région Azure
VM_SIZE="Standard_B1s"   # Type de machine virtuelle
IMAGE="Canonical:UbuntuServer:18.04-LTS:latest"  # Image Ubuntu
STORAGE_ACCOUNT="<STORAGE-Name-Here>"  # Compte de stockage pour les scripts
CONTAINER_NAME="scripts"   # Nom du conteneur Blob
PROXY_PORT_BASE=30000      # Port de départ pour les proxies

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

# Vérifier si le compte de stockage existe dans le groupe de ressources
EXISTING_STORAGE_ACCOUNT=$(az storage account show --name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" --query "name" --output tsv 2>/dev/null)

if [[ -z "$EXISTING_STORAGE_ACCOUNT" ]]; then
    echo "Le compte de stockage $STORAGE_ACCOUNT n'existe pas dans le groupe de ressources $RESOURCE_GROUP, création en cours..."
    az storage account create --name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" --location "$LOCATION" --sku Standard_LRS
else
    echo "Le compte de stockage $STORAGE_ACCOUNT existe déjà dans le groupe de ressources $RESOURCE_GROUP."
fi

# Récupérer la clé du compte de stockage
STORAGE_KEY=$(az storage account keys list --resource-group "$RESOURCE_GROUP" --account-name "$STORAGE_ACCOUNT" --query "[0].value" --output tsv)

# Créer le conteneur Blob s'il n'existe pas
az storage container create --name "$CONTAINER_NAME" --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY"

# Générer une URL SAS pour le script
SAS_TOKEN=$(az storage blob generate-sas --account-name "$STORAGE_ACCOUNT" --container-name "$CONTAINER_NAME" --name "configure-proxy.sh" --permissions r --expiry $(date -u -d "1 day" '+%Y-%m-%dT%H:%MZ') --output tsv)

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

# Générer les VM
for ((i=0; i<MACHINE_COUNT; i++)); do
    # Incrémenter le proxy port
    PROXY_PORT=$((PROXY_PORT_BASE + i))

    # Nom unique de la machine
    VM_NAME="proxy-vm-$PROXY_PORT"

    # Générer le fichier cloud-init pour chaque VM
    cat <<EOF > cloud-init-$VM_NAME.yaml
#cloud-config
hostname: $VM_NAME
users:
  - name: $PROXY_USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_rsa.pub)

package_update: true
package_upgrade: true

runcmd:
  - wget "$SCRIPT_URL" -O /tmp/configure-proxy.sh >> /var/log/proxy-setup.log 2>&1
  - chmod +x /tmp/configure-proxy.sh >> /var/log/proxy-setup.log 2>&1
  - /tmp/configure-proxy.sh $PROXY_PORT $PROXY_USERNAME $PROXY_PASSWORD >> /var/log/proxy-setup.log 2>&1
EOF

    # Créer la VM avec cloud-init
    az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --image "$IMAGE" \
        --size "$VM_SIZE" \
        --admin-username "$PROXY_USERNAME" \
        --admin-password "$PROXY_PASSWORD" \
        --custom-data cloud-init-$VM_NAME.yaml \
        --no-wait
done

# Final message
echo "Création des machines terminée. Vous pouvez accéder à vos proxies via l'entrypoint $ENTRYPOINT avec les ports suivants :"

for ((i=0; i<MACHINE_COUNT; i++)); do
    PROXY_PORT=$((PROXY_PORT_BASE + i))
    echo "$ENTRYPOINT:$PROXY_PORT"
done
