# AzureProxies

AzureProxies is an automated solution for deploying and configuring proxy servers on Microsoft Azure. It automates the creation of virtual machines (VMs) acting as proxies, including their configuration using Squid proxy, and sets up HAProxy for load balancing.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

This project provides scripts for the automated deployment of multiple proxy VMs on Azure, with a frontend load balancer (HAProxy) managing traffic distribution based on the ports. Each proxy server is individually configured with unique credentials and can be used to manage traffic to different websites or services.

## Features

- Automated deployment of Squid proxy servers on Azure.
- HAProxy configuration for load balancing and traffic routing.
- Individual port allocation per proxy VM.
- Easy configuration through cloud-init scripts and storage blobs.
- Full integration with Azure Resource Manager (ARM) for managing VMs, network security groups (NSGs), and storage.

## Prerequisites

Before you begin, ensure you have the following:

- An active [Microsoft Azure](https://portal.azure.com/) subscription.
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) installed and authenticated with your Azure account.
- Basic knowledge of Azure VM and networking configurations.
- `bash` shell for running the scripts.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Griffith666/AzureProxies.git
    cd AzureProxies
    ```

2. Ensure you are authenticated with the Azure CLI:

    ```bash
    az login
    ```

3. Configure the required environment variables by editing the variables in the  script:

    - `RESOURCE_GROUP`
    - `LOCATION`
    - `STORAGE_ACCOUNT`
    - `CONTAINER_NAME`
    - `PROXY_PORT_BASE`
