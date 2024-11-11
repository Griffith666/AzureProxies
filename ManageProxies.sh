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
    printf "%-5s %-20s %-15s\n" "#" "Nom" "Statut"
    printf "%-5s %-20s %-15s\n" "---" "--------------------" "---------------"

    # Compteur pour la numérotation
    local counter=1

    # Récupérer la liste des VMs et leur statut
    while IFS=$'\t' read -r name powerState; do
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
        
        # Afficher la ligne avec la couleur appropriée
        printf "%-5s %-20s ${status_color}%-15s${NC}\n" "$counter" "$name" "$status"
        
        ((counter++))
    done < <(az vm list \
        --resource-group "$RESOURCE_GROUP" \
        --show-details \
        --query "[].{name:name, powerState:powerState}" \
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

# Fonction pour supprimer une ou plusieurs VMs
delete_vms() {
    local selection=$1
    
    if [ -n "$selection" ]; then
        # Convertir la sélection en noms de VMs
        local vm_names=$(convert_selection_to_names "$selection")
        if [ $? -ne 0 ]; then
            return 1
        fi
        
        for vm in $vm_names; do
            info_msg "Suppression de la VM $vm..."
            if az vm delete --resource-group "$RESOURCE_GROUP" --name "$vm" --yes --no-wait; then
                success_msg "Suppression de $vm lancée"
            else
                error_msg "Échec de la suppression de $vm"
            fi
        done
    else
        info_msg "ATTENTION: Vous allez supprimer toutes les VMs!"
        read -p "Êtes-vous sûr? (oui/non): " confirm
        if [ "$confirm" = "oui" ]; then
            for vm in "${VM_NAMES[@]}"; do
                info_msg "- Suppression VM: $vm"
                if az vm delete --resource-group "$RESOURCE_GROUP" --name "$vm" --yes --no-wait; then
                    success_msg "Suppression de $vm lancée"
                else
                    error_msg "Échec de la suppression de $vm"
                fi
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