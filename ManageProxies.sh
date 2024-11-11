#!/bin/bash

# Variables de configuration
RESOURCE_GROUP="RG-Proxies"

# Variables pour les couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

    # En-tête du tableau
    printf "%-20s %-15s\n" "Nom" "Statut"
    printf "%-20s %-15s\n" "--------------------" "---------------"

    # Récupérer la liste des VMs et leur statut
    az vm list \
        --resource-group "$RESOURCE_GROUP" \
        --show-details \
        --query "[].{name:name, powerState:powerState}" \
        -o tsv | while read -r name powerState; do
            # Définir la couleur en fonction du statut
            if [[ "$powerState" == *"running"* ]]; then
                status_color=$GREEN
                status="RUNNING"
            else
                status_color=$YELLOW
                status="STOPPED"
            fi
            
            # Afficher la ligne avec la couleur appropriée
            printf "%-20s ${status_color}%-15s${NC}\n" "$name" "$status"
        done

    echo
}

# [Le reste du script reste identique...]

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
                read -p "Nom de la VM (vide pour toutes): " vm_name
                manage_vm_power "$action" "$vm_name"
                ;;
            3)
                read -p "Nom de la VM (vide pour toutes): " vm_name
                delete_vms "$vm_name"
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