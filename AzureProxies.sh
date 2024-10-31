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
# Charger les variables de configuration depuis proxy-vars.sh
source /tmp/proxy-vars.sh

echo "VM_NAME: $VM_NAME"
echo "PROXY_PORT: $PROXY_PORT"
echo "PROXY_USERNAME: $PROXY_USERNAME"

# Configuration du serveur proxy
sudo apt update && sudo apt upgrade -y && sudo apt install -y squid apache2-utils

echo "Creating VM: $VM_NAME with port: $PROXY_PORT, username: $PROXY_USERNAME"

sudo htpasswd -bc /etc/squid/squid_passwd "$PROXY_USERNAME" "$PROXY_PASSWORD"

# Configurer Squid avec authentification et spécifier le port
sudo tee /etc/squid/squid.conf <<EOL
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/squid_passwd
auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off

acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all

http_port 3128

# Logs
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
EOL

# Corriger les permissions sur les dossiers de logs
sudo chown -R proxy:proxy /var/log/squid
sudo chmod -R 755 /var/log/squid

# Redémarrer Squid
sudo systemctl restart squid

echo "Squid configuré avec succès sur le port $PROXY_PORT."
EOF

cat <<EOF > configure-haproxy.sh
#!/bin/bash
# Charger les variables de configuration depuis haproxy-vars.sh
source /tmp/haproxy-vars.sh


# Debugging: Afficher les variables pour vérification
echo "HAPROXY_FRONTENDS: $HAPROXY_FRONTENDS"
echo "HAPROXY_BACKENDS: $HAPROXY_BACKENDS"

# Vérifier si HAProxy est déjà configuré
if [ -f /etc/haproxy/haproxy.cfg ]; then
  echo "HAProxy configuration found. Updating configuration..."
else
  echo "No HAProxy configuration found. Creating new configuration..."
fi

# Créer ou mettre à jour la configuration HAProxy
sudo tee /etc/haproxy/haproxy.cfg <<EOL
defaults
  mode tcp
  timeout connect 5000ms
  timeout client  50000ms
  timeout server  50000ms

frontend http-in
  bind *:80
  default_backend proxy-backends

$HAPROXY_FRONTENDS

backend proxy-backends
$HAPROXY_BACKENDS
EOL

# Redémarrer HAProxy
sudo systemctl restart haproxy

# Activer HAProxy au démarrage
sudo systemctl enable haproxy

echo "HAProxy configuration terminée et démarrée avec succès."
EOF

# Charger le script dans le Blob Storage
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "configure-proxy.sh" --file "configure-proxy.sh" --auth-mode login
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "configure-haproxy.sh" --file "configure-haproxy.sh" --auth-mode login

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

    # Ouvrir temporairement le port 22 pour le débogage SSH
    echo "Ajout de la règle pour ouvrir temporairement le port 22 (SSH) dans le NSG $NSG_NAME"
    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG_NAME" \
        --name "Allow-SSH-Temporary" \
        --priority 100 \
        --destination-port-ranges 22 \
        --protocol Tcp \
        --access Allow \
        --direction Inbound

    # Attacher le NSG à l'interface réseau de la VM HAProxy
    NIC_ID=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$FRONTEND_VM" --query "networkProfile.networkInterfaces[0].id" --output tsv)
    if [[ -n "$NIC_ID" ]]; then
        echo "Association du NSG $NSG_NAME à la NIC $NIC_ID de HAProxy..."
        az network nic update --ids "$NIC_ID" --network-security-group "$NSG_NAME"
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
    HAPROXY_BACKENDS+="  server $VM $IP:3128 check\n"
    HAPROXY_FRONTENDS+="  use_backend $VM if { hdr_beg(host) -i $ENTRYPOINT:$PORT }\n"
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

    # Ajouter la nouvelle machine à HAProxy
    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query publicIps --output tsv)
    HAPROXY_BACKENDS+="  server $VM_NAME $IP:3128 check\n"
    HAPROXY_FRONTENDS+="  use_backend $VM_NAME if { hdr_beg(host) -i $ENTRYPOINT:$PROXY_PORT }\n"
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

# Création d'un fichier de variables pour HAProxy
cat <<EOF > haproxy-vars.sh
HAPROXY_FRONTENDS="$HAPROXY_FRONTENDS"
HAPROXY_BACKENDS="$HAPROXY_BACKENDS"
EOF

# Charger le fichier de variables HAProxy dans le stockage Azure
az storage blob upload --account-name "$STORAGE_ACCOUNT" --account-key "$STORAGE_KEY" --container-name "$CONTAINER_NAME" --name "haproxy-vars.sh" --file "haproxy-vars.sh" --auth-mode login


# Générer le cloud-init pour HAProxy
cat <<EOF > cloud-init-haproxy.yaml
#cloud-config
runcmd:
  - echo "Downloading HAProxy configuration script..."
  - curl -o /tmp/configure-haproxy.sh "$SCRIPT_URL_HAPROXY"
  - curl -o /tmp/haproxy-vars.sh "https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER_NAME/haproxy-vars.sh?$SAS_TOKEN_HAPROXY"
  - chmod +x /tmp/configure-haproxy.sh /tmp/haproxy-vars.sh
  - |
    source /tmp/haproxy-vars.sh
    /tmp/configure-haproxy.sh

EOF

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