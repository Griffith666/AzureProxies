#!/bin/bash

# Variables de configuration
RESOURCE_GROUP="RG-Leo"
SUBSCRIPTION_ID=""  # Optionnel : si vous voulez forcer une subscription spécifique

# Variables pour les couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Tableau global pour stocker les noms des VMs
declare -a VM_NAMES

# Fonction pour afficher les messages d'erreur
error_msg() {
    echo -e "${RED}[ERREUR]${NC} $1"
}

# Fonction pour afficher les messages de succès
success_msg() {
    echo -e "${GREEN}[SUCCÈS]${NC} $1"
}

# Fonction pour afficher les messages d'information
info_msg() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Fonction pour obtenir la liste des VMs avec leurs infos
get_vm_list() {
    info_msg "Récupération des informations des VMs..."
    
    # Vérifier s'il y a des VMs dans le groupe de ressources
    local vm_count=$(az vm list -g "$RESOURCE_GROUP" --query "length(@)")
    if [ "$vm_count" -eq 0 ]; then
        error_msg "Aucune VM trouvée dans le groupe de ressources $RESOURCE_GROUP"
        return 1
    fi

    # Réinitialiser le tableau des VMs
    VM_NAMES=()

    # En-tête du tableau
    printf "%-5s %-20s %-15s %-15s\n" "#" "Nom" "Statut" "IP Publique"
    printf "%-5s %-20s %-15s %-15s\n" "---" "--------------------" "---------------" "---------------"

    # Compteur pour la numérotation
    local counter=1

    # Récupérer la liste des VMs et leur statut
    while IFS=$'\t' read -r name powerState publicIP; do
        # Ajouter le nom de la VM au tableau global
        VM_NAMES+=("$name")
        
        # Définir la couleur en fonction du statut
        if [[ "$powerState" == *"running"* ]]; then
            status_color=$GREEN
            status="RUNNING"
        else
            status_color=$YELLOW
            status="STOPPED"
        fi

        # Si l'IP est vide, afficher "Non attribuée"
        if [ -z "$publicIP" ]; then
            publicIP="Non attribuée"
        fi
        
        # Afficher la ligne avec la couleur appropriée
        printf "%-5s %-20s ${status_color}%-15s${NC} %-15s\n" "$counter" "$name" "$status" "$publicIP"
        
        ((counter++))
    done < <(az vm list \
        --resource-group "$RESOURCE_GROUP" \
        --show-details \
        --query "[].{name:name, powerState:powerState, publicIps:publicIps}" \
        -o tsv)

    echo
}

# Fonction pour convertir la sélection en noms de VMs
convert_selection_to_names() {
    local selection=$1
    local selected_vms=()
    
    # Diviser la sélection par virgules
    IFS=',' read -ra numbers <<< "$selection"
    
    # Pour chaque numéro sélectionné
    for num in "${numbers[@]}"; do
        # Enlever les espaces
        num=$(echo "$num" | tr -d ' ')
        
        # Vérifier si le numéro est valide
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#VM_NAMES[@]}" ]; then
            selected_vms+=("${VM_NAMES[$num-1]}")
        else
            error_msg "Numéro invalide: $num"
            return 1
        fi
    done
    
    echo "${selected_vms[@]}"
}

# Fonction pour démarrer/arrêter une ou plusieurs VMs
manage_vm_power() {
    local action=$1
    local selection=$2
    
    if [ "$action" != "start" ] && [ "$action" != "stop" ]; then
        error_msg "Action invalide. Utilisez 'start' ou 'stop'"
        return 1
    fi
    
    if [ -n "$selection" ]; then
        # Convertir la sélection en noms de VMs
        local vm_names=$(convert_selection_to_names "$selection")
        if [ $? -ne 0 ]; then
            return 1
        fi
        
        for vm in $vm_names; do
            info_msg " $action VM $vm..."
            if az vm $action --resource-group "$RESOURCE_GROUP" --name "$vm" --no-wait; then
                success_msg "Action $action lancée pour $vm"
            else
                error_msg "Échec de l'action $action pour $vm"
            fi
        done
    else
        info_msg "Application de l'action $action sur toutes les VMs..."
        for vm in "${VM_NAMES[@]}"; do
            info_msg "- $action VM: $vm"
            if az vm $action --resource-group "$RESOURCE_GROUP" --name "$vm" --no-wait; then
                success_msg "Action $action lancée pour $vm"
            else
                error_msg "Échec de l'action $action pour $vm"
            fi
        done
    fi
}

# Fonction pour supprimer tous les éléments associés à une VM
delete_vm_resources() {
    local vm_name=$1
    info_msg "Suppression de tous les éléments associés à $vm_name..."
    
    # Obtenir l'ID de la VM
    local vm_id=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$vm_name" --query "id" -o tsv 2>/dev/null)
    if [ -z "$vm_id" ]; then
        error_msg "VM $vm_name non trouvée"
        return 1
    fi

    # Récupérer les informations des ressources
    local os_disk=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$vm_name" --query "storageProfile.osDisk.name" -o tsv)
    local data_disks=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$vm_name" --query "storageProfile.dataDisks[].name" -o tsv)

    # Variations possibles pour le nom de l'interface réseau
    local nic_variations=("${vm_name}VMNic" "${vm_name}VNic" "${vm_name}-nic" "${vm_name}VNET" "${vm_name}VMNic0")
    local nic_name=""

    # Trouver le bon nom de l'interface réseau
    for variation in "${nic_variations[@]}"; do
        if az network nic show --resource-group "$RESOURCE_GROUP" --name "$variation" &>/dev/null; then
            nic_name="$variation"
            info_msg "Interface réseau trouvée : $nic_name"
            break
        fi
    done

    # Si aucune interface réseau n'est trouvée, essayer de la trouver via la VM
    if [ -z "$nic_name" ]; then
        local nic_id=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$vm_name" \
            --query "networkProfile.networkInterfaces[0].id" -o tsv)
        if [ -n "$nic_id" ]; then
            nic_name=$(basename "$nic_id")
            info_msg "Interface réseau trouvée via VM : $nic_name"
        fi
    fi

    # Récupérer les informations du NSG
    local nsg_variations=("${vm_name}-nsg" "${vm_name}NSG" "${vm_name}-NSG" "${vm_name}nsg" "${vm_name}NSG")
    local nsg_name=""
    
    # Trouver le bon nom du NSG
    for variation in "${nsg_variations[@]}"; do
        if az network nsg show --resource-group "$RESOURCE_GROUP" --name "$variation" &>/dev/null; then
            nsg_name="$variation"
            info_msg "NSG trouvé : $nsg_name"
            break
        fi
    done

    local public_ip_name="${vm_name}PublicIP"

    # 1. Vérifier et récupérer les informations de l'interface réseau
    if [ -n "$nic_name" ] && az network nic show --resource-group "$RESOURCE_GROUP" --name "$nic_name" &>/dev/null; then
        # Vérifier si un NSG est attaché
        local attached_nsg=$(az network nic show \
            --resource-group "$RESOURCE_GROUP" \
            --name "$nic_name" \
            --query "networkSecurityGroup.id" -o tsv)
        
        if [ -n "$attached_nsg" ]; then
            info_msg "Dissociation du NSG de l'interface réseau..."
            az network nic update \
                --resource-group "$RESOURCE_GROUP" \
                --name "$nic_name" \
                --network-security-group "" \
                --no-wait
            
            sleep 5
        fi

        # Récupérer le nom de la configuration IP
        local ip_config_name=$(az network nic show \
            --resource-group "$RESOURCE_GROUP" \
            --name "$nic_name" \
            --query "ipConfigurations[0].name" -o tsv)

        # Vérifier si une IP publique est attachée
        local has_public_ip=$(az network nic show \
            --resource-group "$RESOURCE_GROUP" \
            --name "$nic_name" \
            --query "ipConfigurations[0].publicIpAddress.id" -o tsv)
        
        if [ -n "$has_public_ip" ] && [ -n "$ip_config_name" ]; then
            info_msg "Dissociation de l'IP publique de l'interface réseau..."
            az network nic ip-config update \
                --resource-group "$RESOURCE_GROUP" \
                --name "$ip_config_name" \
                --nic-name "$nic_name" \
                --remove publicIpAddress \
                --no-wait
            
            sleep 5
        fi
    fi

    # 2. Supprimer la VM
    info_msg "Suppression de la VM $vm_name..."
    if az vm show --resource-group "$RESOURCE_GROUP" --name "$vm_name" &>/dev/null; then
        az vm delete \
            --resource-group "$RESOURCE_GROUP" \
            --name "$vm_name" \
            --yes \
            --force-deletion true \
            --no-wait
        
        sleep 10
    fi

    # 3. Supprimer l'interface réseau
    if az network nic show --resource-group "$RESOURCE_GROUP" --name "$nic_name" &>/dev/null; then
        info_msg "Suppression de l'interface réseau $nic_name..."
        az network nic delete \
            --resource-group "$RESOURCE_GROUP" \
            --name "$nic_name" \
            --no-wait
        
        sleep 5
    fi

    # 4. Supprimer le NSG si trouvé
    if [ -n "$nsg_name" ]; then
        info_msg "Suppression du NSG $nsg_name..."
        az network nsg delete \
            --resource-group "$RESOURCE_GROUP" \
            --name "$nsg_name" \
            --no-wait
        
        sleep 5
    fi

    # 5. Supprimer l'IP publique
    if az network public-ip show --resource-group "$RESOURCE_GROUP" --name "$public_ip_name" &>/dev/null; then
        info_msg "Suppression de l'IP publique $public_ip_name..."
        az network public-ip delete \
            --resource-group "$RESOURCE_GROUP" \
            --name "$public_ip_name" \
            --no-wait
    fi
    
    # 6. Supprimer les disques
    if [ -n "$os_disk" ]; then
        info_msg "Suppression du disque OS $os_disk..."
        az disk delete --resource-group "$RESOURCE_GROUP" --name "$os_disk" --yes --no-wait
    fi
    
    for data_disk in $data_disks; do
        info_msg "Suppression du disque de données $data_disk..."
        az disk delete --resource-group "$RESOURCE_GROUP" --name "$data_disk" --yes --no-wait
    done
    
    success_msg "Suppression des ressources de $vm_name lancée"
}

# Fonction modifiée pour supprimer une ou plusieurs VMs
delete_vms() {
    local selection=$1
    
    if [ -n "$selection" ]; then
        # Convertir la sélection en noms de VMs
        local vm_names=$(convert_selection_to_names "$selection")
        if [ $? -ne 0 ]; then
            return 1
        fi
        
        for vm in $vm_names; do
            delete_vm_resources "$vm"
        done
    else
        info_msg "ATTENTION: Vous allez supprimer toutes les VMs et leurs ressources associées!"
        read -p "Êtes-vous sûr? (oui/non): " confirm
        if [ "$confirm" = "oui" ]; then
            for vm in "${VM_NAMES[@]}"; do
                delete_vm_resources "$vm"
            done
        fi
    fi
}
# Menu principal
main() {
    # Vérifications initiales
    check_azure_connection
    check_resource_group
    
    while true; do
        clear
        echo "=== Gestionnaire de VMs Azure ==="
        echo "Groupe de ressources: $RESOURCE_GROUP"
        echo
        
        # Afficher la liste des VMs
        get_vm_list
        
        echo "Options disponibles:"
        echo "1) Démarrer une/toutes les VM(s)"
        echo "2) Arrêter une/toutes les VM(s)"
        echo "3) Supprimer une/toutes les VM(s)"
        echo "4) Quitter"
        echo
        
        read -p "Choisissez une option (1-4): " choice
        echo
        
        case $choice in
            1|2)
                action="start"
                [ "$choice" -eq 2 ] && action="stop"
                read -p "Numéros des VMs (séparés par des virgules, vide pour toutes): " vm_selection
                manage_vm_power "$action" "$vm_selection"
                ;;
            3)
                read -p "Numéros des VMs (séparés par des virgules, vide pour toutes): " vm_selection
                delete_vms "$vm_selection"
                ;;
            4)
                success_msg "Au revoir!"
                exit 0
                ;;
            *)
                error_msg "Option invalide"
                ;;
        esac
        
        read -p "Appuyez sur Entrée pour continuer..."
    done
}

# Auto-exécution du script
{
    main
}