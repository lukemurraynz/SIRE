# SIRE Implementation Guide

## Overview

This guide provides step-by-step instructions for implementing a Secure Isolated Recovery Environment (SIRE) in Microsoft Azure. The implementation follows the Well-Architected Framework principles and includes infrastructure deployment, security configuration, and operational setup.

## Prerequisites

### Administrative Requirements
- Global Administrator access to Microsoft Entra ID tenant
- Subscription Owner or Contributor role in target Azure subscription
- Security Administrator role for security configurations
- Access to domain administration for hybrid scenarios

### Planning Requirements
- Approved SIRE architecture design
- Network addressing scheme
- Security and compliance requirements
- Budget and resource allocation approval

### Technical Requirements
- Azure CLI or PowerShell installed
- Git for Infrastructure as Code (IaC) management
- Terraform or Bicep for infrastructure deployment
- Administrative workstation with required tools

## Implementation Phases

### Phase 1: Foundation Infrastructure (Weeks 1-2)

#### 1.1 Resource Group and Subscription Setup

**Create Resource Groups**:
```bash
# Primary SIRE resource group
az group create \
  --name "rg-sire-primary-prod" \
  --location "East US 2" \
  --tags Environment=SIRE Project=Recovery

# Secondary SIRE resource group (different region)
az group create \
  --name "rg-sire-secondary-prod" \
  --location "West US 2" \
  --tags Environment=SIRE Project=Recovery
```

**Apply Resource Locks**:
```bash
# Prevent accidental deletion
az lock create \
  --lock-type CanNotDelete \
  --name "SIRE-Protection-Lock" \
  --resource-group "rg-sire-primary-prod"
```

#### 1.2 Network Infrastructure

**Virtual Network Creation**:
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vnetName": {
      "type": "string",
      "defaultValue": "vnet-sire-primary"
    },
    "vnetAddressSpace": {
      "type": "string",
      "defaultValue": "10.100.0.0/16"
    }
  },
  "resources": [
    {
      "type": "Microsoft.Network/virtualNetworks",
      "apiVersion": "2021-05-01",
      "name": "[parameters('vnetName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "addressSpace": {
          "addressPrefixes": [
            "[parameters('vnetAddressSpace')]"
          ]
        },
        "subnets": [
          {
            "name": "AzureFirewallSubnet",
            "properties": {
              "addressPrefix": "10.100.0.0/26"
            }
          },
          {
            "name": "AzureBastionSubnet",
            "properties": {
              "addressPrefix": "10.100.0.64/26"
            }
          },
          {
            "name": "snet-management",
            "properties": {
              "addressPrefix": "10.100.1.0/24"
            }
          },
          {
            "name": "snet-recovery",
            "properties": {
              "addressPrefix": "10.100.2.0/24"
            }
          },
          {
            "name": "snet-forensics",
            "properties": {
              "addressPrefix": "10.100.3.0/24"
            }
          },
          {
            "name": "snet-backup",
            "properties": {
              "addressPrefix": "10.100.4.0/24"
            }
          }
        ]
      }
    }
  ]
}
```

**Deploy Network Infrastructure**:
```bash
az deployment group create \
  --resource-group "rg-sire-primary-prod" \
  --template-file "templates/network.json" \
  --parameters vnetName="vnet-sire-primary"
```

#### 1.3 Network Security Groups

**Management Subnet NSG**:
```bash
# Create NSG for management subnet
az network nsg create \
  --resource-group "rg-sire-primary-prod" \
  --name "nsg-management" \
  --location "East US 2"

# Allow RDP from Bastion
az network nsg rule create \
  --resource-group "rg-sire-primary-prod" \
  --nsg-name "nsg-management" \
  --name "Allow-RDP-from-Bastion" \
  --priority 100 \
  --source-address-prefixes "10.100.0.64/26" \
  --source-port-ranges "*" \
  --destination-address-prefixes "10.100.1.0/24" \
  --destination-port-ranges "3389" \
  --access "Allow" \
  --protocol "Tcp"

# Associate NSG with subnet
az network vnet subnet update \
  --resource-group "rg-sire-primary-prod" \
  --vnet-name "vnet-sire-primary" \
  --name "snet-management" \
  --network-security-group "nsg-management"
```

#### 1.4 Azure Bastion Deployment

```bash
# Create public IP for Bastion
az network public-ip create \
  --resource-group "rg-sire-primary-prod" \
  --name "pip-bastion-sire" \
  --sku "Standard" \
  --allocation-method "Static"

# Deploy Azure Bastion
az network bastion create \
  --resource-group "rg-sire-primary-prod" \
  --name "bastion-sire-primary" \
  --public-ip-address "pip-bastion-sire" \
  --vnet-name "vnet-sire-primary" \
  --location "East US 2" \
  --sku "Standard"
```

### Phase 2: Security Infrastructure (Weeks 2-3)

#### 2.1 Azure Key Vault

**Key Vault Deployment**:
```bash
# Create Key Vault
az keyvault create \
  --resource-group "rg-sire-primary-prod" \
  --name "kv-sire-primary-prod" \
  --location "East US 2" \
  --enable-soft-delete true \
  --enable-purge-protection true \
  --retention-days 90 \
  --sku "Premium"

# Configure network access
az keyvault network-rule add \
  --resource-group "rg-sire-primary-prod" \
  --name "kv-sire-primary-prod" \
  --vnet-name "vnet-sire-primary" \
  --subnet "snet-management"

az keyvault update \
  --resource-group "rg-sire-primary-prod" \
  --name "kv-sire-primary-prod" \
  --default-action "Deny"
```

**Emergency Access Keys**:
```powershell
# Generate emergency access credentials
$EmergencyPassword = New-Guid | Select-Object -ExpandProperty Guid
$SecurePassword = ConvertTo-SecureString $EmergencyPassword -AsPlainText -Force

# Store in Key Vault
Set-AzKeyVaultSecret \
  -VaultName "kv-sire-primary-prod" \
  -Name "emergency-admin-password" \
  -SecretValue $SecurePassword \
  -ContentType "Emergency Access Credential"
```

#### 2.2 Azure Firewall

**Firewall Deployment**:
```bash
# Create public IP for Firewall
az network public-ip create \
  --resource-group "rg-sire-primary-prod" \
  --name "pip-firewall-sire" \
  --sku "Standard" \
  --allocation-method "Static"

# Deploy Azure Firewall
az network firewall create \
  --resource-group "rg-sire-primary-prod" \
  --name "fw-sire-primary" \
  --location "East US 2" \
  --vnet-name "vnet-sire-primary" \
  --public-ip "pip-firewall-sire" \
  --sku "Standard" \
  --tier "Standard"
```

**Firewall Rules**:
```bash
# Create application rule collection
az network firewall application-rule collection create \
  --resource-group "rg-sire-primary-prod" \
  --firewall-name "fw-sire-primary" \
  --name "AllowAzureServices" \
  --priority 100 \
  --action "Allow"

# Allow Azure services
az network firewall application-rule create \
  --resource-group "rg-sire-primary-prod" \
  --firewall-name "fw-sire-primary" \
  --collection-name "AllowAzureServices" \
  --name "Azure-Services" \
  --source-addresses "10.100.0.0/16" \
  --protocols "https=443" \
  --fqdn-tags "MicrosoftEntraID" "AzureBackup" "AzureKeyVault"
```

#### 2.3 Private Endpoints

**Storage Account Private Endpoint**:
```bash
# Create storage account
az storage account create \
  --resource-group "rg-sire-primary-prod" \
  --name "stsirebackupprimary" \
  --location "East US 2" \
  --sku "Standard_GRS" \
  --kind "StorageV2" \
  --access-tier "Hot" \
  --https-only true

# Create private endpoint
az network private-endpoint create \
  --resource-group "rg-sire-primary-prod" \
  --name "pe-storage-sire" \
  --vnet-name "vnet-sire-primary" \
  --subnet "snet-backup" \
  --private-connection-resource-id "/subscriptions/{subscription-id}/resourceGroups/rg-sire-primary-prod/providers/Microsoft.Storage/storageAccounts/stsirebackupprimary" \
  --group-id "blob" \
  --connection-name "storage-private-connection"
```

### Phase 3: Backup and Recovery Services (Weeks 3-4)

#### 3.1 Recovery Services Vault

**Vault Creation**:
```bash
# Create Recovery Services Vault
az backup vault create \
  --resource-group "rg-sire-primary-prod" \
  --name "rsv-sire-primary" \
  --location "East US 2" \
  --storage-model-type "GeoRedundant"

# Configure vault properties
az backup vault backup-properties set \
  --resource-group "rg-sire-primary-prod" \
  --name "rsv-sire-primary" \
  --soft-delete-feature-state "Enabled" \
  --storage-model-type "GeoRedundant" \
  --storage-type "GeoRedundant"
```

**Immutable Vault Configuration**:
```bash
# Enable immutable vault (irreversible)
az backup vault immutability-state set \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --immutability-state "Enabled"
```

#### 3.2 Backup Policies

**VM Backup Policy**:
```json
{
  "name": "SIRE-Critical-VM-Policy",
  "properties": {
    "backupManagementType": "AzureIaasVM",
    "schedulePolicy": {
      "schedulePolicyType": "SimpleSchedulePolicy",
      "scheduleRunFrequency": "Daily",
      "scheduleRunTimes": ["2023-01-01T02:00:00.000Z"]
    },
    "retentionPolicy": {
      "retentionPolicyType": "LongTermRetentionPolicy",
      "dailySchedule": {
        "retentionTimes": ["2023-01-01T02:00:00.000Z"],
        "retentionDuration": {
          "count": 90,
          "durationType": "Days"
        }
      },
      "weeklySchedule": {
        "retentionTimes": ["2023-01-01T02:00:00.000Z"],
        "retentionDuration": {
          "count": 52,
          "durationType": "Weeks"
        },
        "daysOfTheWeek": ["Sunday"]
      },
      "monthlySchedule": {
        "retentionTimes": ["2023-01-01T02:00:00.000Z"],
        "retentionDuration": {
          "count": 36,
          "durationType": "Months"
        },
        "retentionScheduleFormatType": "Weekly",
        "retentionScheduleWeekly": {
          "daysOfTheWeek": ["Sunday"],
          "weeksOfTheMonth": ["First"]
        }
      },
      "yearlySchedule": {
        "retentionTimes": ["2023-01-01T02:00:00.000Z"],
        "retentionDuration": {
          "count": 7,
          "durationType": "Years"
        },
        "retentionScheduleFormatType": "Weekly",
        "retentionScheduleWeekly": {
          "daysOfTheWeek": ["Sunday"],
          "weeksOfTheMonth": ["First"]
        },
        "monthsOfYear": ["January"]
      }
    }
  }
}
```

**Create Backup Policy**:
```bash
az backup policy create \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --name "SIRE-Critical-VM-Policy" \
  --policy "vm-backup-policy.json"
```

### Phase 4: Compute Infrastructure (Weeks 4-5)

#### 4.1 Virtual Machine Deployment

**Management VM**:
```bash
# Create availability set
az vm availability-set create \
  --resource-group "rg-sire-primary-prod" \
  --name "as-sire-management" \
  --platform-fault-domain-count 2 \
  --platform-update-domain-count 5

# Create management VM
az vm create \
  --resource-group "rg-sire-primary-prod" \
  --name "vm-sire-mgmt-01" \
  --image "Win2022Datacenter" \
  --size "Standard_D4s_v4" \
  --vnet-name "vnet-sire-primary" \
  --subnet "snet-management" \
  --nsg "" \
  --public-ip-address "" \
  --availability-set "as-sire-management" \
  --admin-username "sire-admin" \
  --generate-ssh-keys
```

**Recovery Environment VMs**:
```bash
# Create recovery VM
az vm create \
  --resource-group "rg-sire-primary-prod" \
  --name "vm-sire-recovery-01" \
  --image "Win2022Datacenter" \
  --size "Standard_D8s_v4" \
  --vnet-name "vnet-sire-primary" \
  --subnet "snet-recovery" \
  --nsg "" \
  --public-ip-address "" \
  --admin-username "sire-admin" \
  --generate-ssh-keys
```

#### 4.2 VM Configuration and Hardening

**Security Baseline Configuration**:
```powershell
# Install security agents
Install-Module -Name Az.Security -Force
Enable-AzSecurityAutoProvisioning -ResourceGroupName "rg-sire-primary-prod"

# Configure Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -MAPSReporting 2

# Enable Windows Firewall
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
```

### Phase 5: Monitoring and Alerting (Weeks 5-6)

#### 5.1 Log Analytics Workspace

**Workspace Creation**:
```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group "rg-sire-primary-prod" \
  --workspace-name "law-sire-primary" \
  --location "East US 2" \
  --sku "PerGB2018" \
  --retention-time 90
```

**Data Sources Configuration**:
```bash
# Enable VM monitoring
az monitor log-analytics workspace pack enable \
  --resource-group "rg-sire-primary-prod" \
  --workspace-name "law-sire-primary" \
  --name "Security"

az monitor log-analytics workspace pack enable \
  --resource-group "rg-sire-primary-prod" \
  --workspace-name "law-sire-primary" \
  --name "Updates"
```

#### 5.2 Microsoft Sentinel

**Sentinel Onboarding**:
```bash
# Enable Sentinel
az sentinel workspace create \
  --resource-group "rg-sire-primary-prod" \
  --workspace-name "law-sire-primary"
```

**Data Connectors**:
```json
{
  "connectors": [
    {
      "kind": "MicrosoftEntraID",
      "properties": {
        "tenantId": "{tenant-id}",
        "dataTypes": {
          "signInLogs": {
            "state": "Enabled"
          },
          "auditLogs": {
            "state": "Enabled"
          }
        }
      }
    },
    {
      "kind": "AzureSecurityCenter",
      "properties": {
        "subscriptionId": "{subscription-id}",
        "dataTypes": {
          "alerts": {
            "state": "Enabled"
          }
        }
      }
    }
  ]
}
```

### Phase 6: Identity and Access Management (Weeks 6-7)

> **🎯 Primary Implementation: Same-Tenant RBAC Isolation**
> 
> This section provides implementation guidance for the recommended same-tenant approach, where SIRE operates within your existing Microsoft Entra ID tenant using strict RBAC boundaries.

#### 6.1 Same-Tenant Identity Isolation Strategy

**Identity Isolation Principles:**
- **Dedicated Security Groups**: SIRE-specific groups with no overlap to production
- **Scoped RBAC Roles**: Custom roles limited to SIRE resource groups only  
- **Conditional Access Controls**: SIRE-specific policies for enhanced security
- **Privileged Access Management**: PIM and JIT for administrative access
- **Separate Service Identities**: Dedicated managed identities for SIRE services

**Implementation Approach:**
1. Create SIRE-specific security groups
2. Define custom RBAC roles scoped to SIRE resources
3. Configure conditional access policies for SIRE access
4. Implement PIM for administrative roles
5. Set up emergency access accounts

#### 6.2 Microsoft Entra ID Groups and Roles

**Create SIRE Groups**:
```powershell
# Connect to Microsoft Entra ID
Connect-AzureAD

# Create SIRE administrator group
New-AzureADGroup -DisplayName "SIRE-Administrators" `
  -MailEnabled $false `
  -SecurityEnabled $true `
  -MailNickName "SIREAdmins" `
  -Description "SIRE Environment Administrators"

# Create SIRE operators group
New-AzureADGroup -DisplayName "SIRE-Operators" `
  -MailEnabled $false `
  -SecurityEnabled $true `
  -MailNickName "SIREOps" `
  -Description "SIRE Environment Operators"

# Create forensics analysts group
New-AzureADGroup -DisplayName "SIRE-Forensics" `
  -MailEnabled $false `
  -SecurityEnabled $true `
  -MailNickName "SIREForensics" `
  -Description "SIRE Forensics Analysts"
```

**Add Members to SIRE Groups**:
```powershell
# Add users to appropriate SIRE groups
Add-AzureADGroupMember -ObjectId (Get-AzureADGroup -Filter "DisplayName eq 'SIRE-Administrators'").ObjectId -RefObjectId (Get-AzureADUser -Filter "UserPrincipalName eq 'admin@contoso.com'").ObjectId

# Verify group membership
Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -Filter "DisplayName eq 'SIRE-Administrators'").ObjectId
```

#### 6.3 Same-Tenant Conditional Access Policies

**SIRE-Specific Conditional Access Policy**:
```json
{
  "displayName": "SIRE-Same-Tenant-Access-Policy",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeGroups": ["SIRE-Administrators", "SIRE-Operators", "SIRE-Forensics"]
    },
    "applications": {
      "includeApplications": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]
    },
    "locations": {
      "includeLocations": ["SIRE-Trusted-Locations"],
      "excludeLocations": ["AllTrusted"]
    },
    "deviceStates": {
      "includeStates": ["All"],
      "excludeStates": ["compliant", "domainJoined"]
    }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": [
      "mfa",
      "compliantDevice",
      "approvedApplication"
    ]
  },
  "sessionControls": {
    "applicationEnforcedRestrictions": {
      "isEnabled": true
    },
    "signInFrequency": {
      "value": 4,
      "type": "hours",
      "isEnabled": true
    }
  }
}
```

**Create Named Location for SIRE Network**:
```powershell
# Create named location for SIRE network access
New-AzureADMSNamedLocationPolicy `
  -DisplayName "SIRE-Network-Location" `
  -IpRanges @("10.100.0.0/16") `
  -IsTrusted $true
```

#### 6.4 Custom RBAC Roles

**SIRE Recovery Operator Role**:
```json
{
  "Name": "SIRE Recovery Operator",
  "Description": "Can perform recovery operations in SIRE environment",
  "Actions": [
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/restart/action",
    "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/read",
    "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/read",
    "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read"
  ],
  "NotActions": [
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.RecoveryServices/vaults/delete",
    "Microsoft.Storage/storageAccounts/delete"
  ],
  "DataActions": [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
  ],
  "NotDataActions": [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
  ],
  "AssignableScopes": [
    "/subscriptions/{subscription-id}/resourceGroups/rg-sire-primary-prod"
  ]
}
```

**Create Custom Role**:
```bash
az role definition create --role-definition "@sire-recovery-operator-role.json"
**Assign RBAC Role to SIRE Groups**:
```bash
# Assign custom role to SIRE operators group
az role assignment create \
  --assignee-object-id $(az ad group show --group "SIRE-Operators" --query objectId -o tsv) \
  --role "SIRE Recovery Operator" \
  --resource-group "rg-sire-primary-prod"
```

#### 6.5 Privileged Identity Management (PIM) for Same-Tenant

**PIM Configuration for SIRE Roles**:
```powershell
# Configure PIM settings for SIRE administrators
$PIMConfig = @{
  RoleDefinitionId = (Get-AzRoleDefinition -Name "SIRE Recovery Operator").Id
  PrincipalId = (Get-AzADGroup -DisplayName "SIRE-Administrators").Id
  ResourceGroup = "rg-sire-primary-prod"
  AssignmentState = "Eligible"
  Duration = "PT4H"
  ApprovalRequired = $true
  JustificationRequired = $true
  MFARequired = $true
}

# Apply PIM configuration
New-AzRoleAssignment @PIMConfig
```

**Same-Tenant PIM Best Practices**:
- **Limited Duration**: Maximum 4-8 hour activations for SIRE access
- **Mandatory Approval**: Require approval from security team or IT director
- **MFA Enforcement**: Require MFA for all PIM activations
- **Justification Required**: Mandate business justification for access requests
- **Regular Reviews**: Quarterly access reviews for all SIRE role assignments

#### 6.6 Emergency Access Accounts (Same-Tenant)

**Create SIRE-Specific Break-Glass Accounts**:
```powershell
# Create emergency account for SIRE-only access
$EmergencyAccount = @{
    DisplayName = "Emergency-SIRE-Admin-01"
    UserPrincipalName = "emergency-sire-admin-01@contoso.com"
    AccountEnabled = $true
    PasswordPolicies = "DisablePasswordExpiration"
    UsageLocation = "US"
}

New-AzureADUser @EmergencyAccount

# Assign to SIRE administrators group only
Add-AzureADGroupMember -ObjectId (Get-AzureADGroup -Filter "DisplayName eq 'SIRE-Administrators'").ObjectId -RefObjectId (Get-AzureADUser -Filter "UserPrincipalName eq 'emergency-sire-admin-01@contoso.com'").ObjectId
```

**Exclude Emergency Accounts from Conditional Access**:
```json
{
  "displayName": "Emergency-Account-Exclusion-Policy",
  "conditions": {
    "users": {
      "excludeUsers": ["emergency-sire-admin-01@contoso.com", "emergency-sire-admin-02@contoso.com"]
    }
  }
}
```

### Phase 7: Testing and Validation (Weeks 7-8)

#### 7.1 Infrastructure Testing

**Connectivity Tests**:
```bash
# Test Bastion connectivity
az network bastion show \
  --resource-group "rg-sire-primary-prod" \
  --name "bastion-sire-primary"

# Test private endpoint resolution
nslookup stsirebackupprimary.blob.core.windows.net
```

**Security Tests**:
```bash
# Verify NSG rules
az network nsg rule list \
  --resource-group "rg-sire-primary-prod" \
  --nsg-name "nsg-management" \
  --output table

# Test firewall rules
az network firewall application-rule collection list \
  --resource-group "rg-sire-primary-prod" \
  --firewall-name "fw-sire-primary"
```

#### 7.2 Backup Testing

**Test VM Backup**:
```bash
# Trigger on-demand backup
az backup protection backup-now \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --container-name "vm-sire-mgmt-01" \
  --item-name "vm-sire-mgmt-01" \
  --retain-until "2024-12-31"

# Monitor backup job
az backup job list \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --status "InProgress"
```

**Test Recovery**:
```bash
# List recovery points
az backup recoverypoint list \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --container-name "vm-sire-mgmt-01" \
  --item-name "vm-sire-mgmt-01"

# Test file recovery
az backup restore files mount-rp \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --container-name "vm-sire-mgmt-01" \
  --item-name "vm-sire-mgmt-01" \
  --rp-name "{recovery-point-name}"
```

## Automation and Infrastructure as Code

### Terraform Configuration

**Main Configuration**:
```hcl
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
    recovery_services_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

# Resource Group
resource "azurerm_resource_group" "sire_primary" {
  name     = "rg-sire-primary-prod"
  location = "East US 2"
  
  tags = {
    Environment = "SIRE"
    Project     = "Recovery"
    CostCenter  = "IT-Security"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "sire_vnet" {
  name                = "vnet-sire-primary"
  address_space       = ["10.100.0.0/16"]
  location            = azurerm_resource_group.sire_primary.location
  resource_group_name = azurerm_resource_group.sire_primary.name
  
  tags = azurerm_resource_group.sire_primary.tags
}

# Subnets
resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.sire_primary.name
  virtual_network_name = azurerm_virtual_network.sire_vnet.name
  address_prefixes     = ["10.100.0.0/26"]
}

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.sire_primary.name
  virtual_network_name = azurerm_virtual_network.sire_vnet.name
  address_prefixes     = ["10.100.0.64/26"]
}

resource "azurerm_subnet" "management" {
  name                 = "snet-management"
  resource_group_name  = azurerm_resource_group.sire_primary.name
  virtual_network_name = azurerm_virtual_network.sire_vnet.name
  address_prefixes     = ["10.100.1.0/24"]
}

# Key Vault
resource "azurerm_key_vault" "sire_kv" {
  name                = "kv-sire-primary-prod"
  location            = azurerm_resource_group.sire_primary.location
  resource_group_name = azurerm_resource_group.sire_primary.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium"
  
  enabled_for_disk_encryption     = true
  enabled_for_deployment          = true
  enabled_for_template_deployment = true
  purge_protection_enabled        = true
  soft_delete_retention_days      = 90
  
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    virtual_network_subnet_ids = [
      azurerm_subnet.management.id
    ]
  }
  
  tags = azurerm_resource_group.sire_primary.tags
}
```

### Deployment Scripts

**PowerShell Deployment Script**:
```powershell
#Requires -Modules Az

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $false)]
    [string]$EnvironmentTag = "SIRE"
)

# Connect to Azure
Connect-AzAccount
Set-AzContext -SubscriptionId $SubscriptionId

# Deploy main template
$DeploymentParameters = @{
    ResourceGroupName     = $ResourceGroupName
    TemplateFile          = ".\templates\main.bicep"
    TemplateParameterFile = ".\parameters\prod.parameters.json"
    Name                  = "SIRE-Deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

Write-Host "Starting SIRE infrastructure deployment..." -ForegroundColor Green
$Deployment = New-AzResourceGroupDeployment @DeploymentParameters

if ($Deployment.ProvisioningState -eq "Succeeded") {
    Write-Host "SIRE infrastructure deployed successfully!" -ForegroundColor Green
    
    # Configure post-deployment settings
    Write-Host "Configuring post-deployment settings..." -ForegroundColor Yellow
    .\scripts\Configure-PostDeployment.ps1 -ResourceGroupName $ResourceGroupName
    
    Write-Host "SIRE deployment completed successfully!" -ForegroundColor Green
} else {
    Write-Error "SIRE deployment failed: $($Deployment.ProvisioningState)"
    Write-Host $Deployment.Error -ForegroundColor Red
    exit 1
}
```

### Infrastructure as Code Best Practices

#### Multi-Environment Strategy

**Environment Structure**:
```
environments/
├── dev/
│   ├── terraform.tfvars
│   ├── backend.tf
│   └── main.tf
├── staging/
│   ├── terraform.tfvars
│   ├── backend.tf
│   └── main.tf
└── production/
    ├── terraform.tfvars
    ├── backend.tf
    └── main.tf
```

**Terraform Variables for Environment Separation**:
```hcl
# variables.tf
variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "tier_configurations" {
  description = "Configuration for different application tiers"
  type = map(object({
    vm_size           = string
    storage_sku       = string
    backup_frequency  = string
    replication_type  = string
  }))
  
  default = {
    tier1 = {
      vm_size          = "Standard_DS4_v2"
      storage_sku      = "Premium_ZRS"
      backup_frequency = "PT1H"  # Every hour
      replication_type = "GRS"
    }
    tier2 = {
      vm_size          = "Standard_D2s_v3"
      storage_sku      = "StandardSSD_LRS"
      backup_frequency = "PT4H"  # Every 4 hours
      replication_type = "LRS"
    }
    tier3 = {
      vm_size          = "Standard_B2s"
      storage_sku      = "Standard_LRS"
      backup_frequency = "P1D"   # Daily
      replication_type = "LRS"
    }
  }
}
```

**State Management**:
```hcl
# backend.tf for production
terraform {
  backend "azurerm" {
    resource_group_name   = "rg-terraform-state"
    storage_account_name  = "stterraformstate"
    container_name        = "terraform-state"
    key                   = "sire/production/terraform.tfstate"
    use_msi              = true
  }
}
```

#### Version Control and Security

**Git Structure**:
```
.gitignore              # Exclude sensitive files
│
├── .github/
│   └── workflows/
│       ├── plan.yml    # Terraform plan on PR
│       └── apply.yml   # Terraform apply on merge
│
├── modules/
│   ├── storage-account/
│   ├── recovery-vault/
│   └── network-security/
│
├── environments/
│   ├── dev/
│   ├── staging/
│   └── production/
│
└── scripts/
    ├── validate.sh
    └── security-scan.sh
```

**Security Scanning in CI/CD**:
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.tfvars'

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform
          
      - name: Run TFLint
        uses: terraform-linters/setup-tflint@v3
        with:
          tflint_version: latest
          
      - name: Run Terraform Security Scan
        run: |
          curl -L "$(curl -s https://api.github.com/repos/aquasecurity/tfsec/releases/latest | grep -o -E "https://.+?tfsec-linux-amd64")" > tfsec
          chmod +x tfsec
          ./tfsec .
```

#### Testing and Validation

**Terraform Testing Framework**:
```hcl
# tests/sire_test.go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestSIREInfrastructure(t *testing.T) {
    terraformOptions := &terraform.Options{
        TerraformDir: "../environments/dev",
        VarFiles:     []string{"terraform.tfvars"},
    }

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)

    // Test resource group exists
    resourceGroupName := terraform.Output(t, terraformOptions, "resource_group_name")
    assert.NotEmpty(t, resourceGroupName)

    // Test Key Vault security
    keyVaultName := terraform.Output(t, terraformOptions, "key_vault_name")
    assert.Contains(t, keyVaultName, "kv-sire")
}
```

**Pre-commit Hooks**:
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.77.0
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_docs
      - id: terraform_tflint
      - id: checkov
        args: [--framework, terraform]
```

#### Compliance and Governance

**Azure Policy Integration**:
```hcl
# policy.tf
resource "azurerm_policy_definition" "sire_security" {
  name         = "sire-security-requirements"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "SIRE Security Requirements"

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field = "type"
          equals = "Microsoft.Storage/storageAccounts"
        },
        {
          field = "tags['Environment']"
          equals = "SIRE"
        }
      ]
    }
    then = {
      effect = "audit"
      details = {
        type = "Microsoft.Storage/storageAccounts"
        existenceCondition = {
          allOf = [
            {
              field = "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"
              equals = true
            },
            {
              field = "Microsoft.Storage/storageAccounts/minimumTlsVersion"
              equals = "TLS1_2"
            }
          ]
        }
      }
    }
  })
}

resource "azurerm_policy_assignment" "sire_security" {
  name                 = "sire-security-assignment"
  scope                = azurerm_resource_group.sire_primary.id
  policy_definition_id = azurerm_policy_definition.sire_security.id
  display_name         = "SIRE Security Policy Assignment"
}
```

**Cost Management**:
```hcl
# cost-management.tf
resource "azurerm_consumption_budget_resource_group" "sire_budget" {
  name              = "budget-sire-monthly"
  resource_group_id = azurerm_resource_group.sire_primary.id

  amount     = 5000
  time_grain = "Monthly"

  time_period {
    start_date = "2024-01-01T00:00:00Z"
    end_date   = "2025-12-31T23:59:59Z"
  }

  notification {
    enabled   = true
    threshold = 80
    operator  = "GreaterThan"
    
    contact_emails = [
      "sire-admin@company.com",
      "finance@company.com"
    ]
  }

  notification {
    enabled   = true
    threshold = 100
    operator  = "GreaterThan"
    
    contact_emails = [
      "sire-admin@company.com",
      "cto@company.com"
    ]
  }
}
```

#### Shared Infrastructure Components

**Centralized Ingress Management**:
```hcl
# shared-ingress.tf
module "shared_ingress" {
  source = "./modules/shared-ingress"
  
  resource_group_name = azurerm_resource_group.shared_services.name
  location           = azurerm_resource_group.shared_services.location
  
  # Azure Firewall for centralized network security
  firewall_config = {
    tier = "Premium"
    dns_servers = ["168.63.129.16"]
    threat_intel_mode = "Alert"
  }
  
  # Web Application Firewall for web applications
  waf_config = {
    sku_name = "WAF_v2"
    sku_tier = "WAF_v2"
    sku_capacity = 2
    
    waf_configuration = {
      enabled          = true
      firewall_mode    = "Prevention"
      rule_set_type    = "OWASP"
      rule_set_version = "3.2"
    }
  }
  
  # Azure Front Door for global load balancing
  frontdoor_config = {
    sku_name = "Premium_AzureFrontDoor"
    
    waf_policy = {
      enabled = true
      mode    = "Prevention"
      
      managed_rules = [
        {
          type    = "DefaultRuleSet"
          version = "1.0"
          action  = "Block"
        },
        {
          type    = "Microsoft_BotManagerRuleSet"
          version = "1.0"
          action  = "Block"
        }
      ]
    }
  }
  
  tags = local.common_tags
}

# Shared services resource group
resource "azurerm_resource_group" "shared_services" {
  name     = "rg-sire-shared-services-${var.environment}"
  location = var.primary_location
  
  tags = merge(local.common_tags, {
    Purpose = "SharedServices"
    Tier    = "Infrastructure"
  })
}
```

**Multi-Tier Application Deployment**:
```hcl
# multi-tier-application.tf
module "tier1_applications" {
  source = "./modules/application-tier"
  
  for_each = var.tier1_applications
  
  application_name    = each.key
  tier               = "tier1"
  resource_group_name = azurerm_resource_group.sire_primary.name
  
  vm_config = var.tier_configurations.tier1
  
  # Tier 1 applications get dedicated ingress
  dedicated_ingress = true
  
  # Premium backup and recovery
  backup_config = {
    frequency = "PT1H"
    retention_days = 365
    geo_replicated = true
  }
  
  # Enhanced monitoring
  monitoring_config = {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.sire.id
    enable_advanced_monitoring = true
    alert_thresholds = {
      cpu_percentage = 70
      memory_percentage = 80
      disk_percentage = 85
    }
  }
  
  tags = merge(local.common_tags, {
    Tier = "1"
    Criticality = "Critical"
  })
}

module "tier2_applications" {
  source = "./modules/application-tier"
  
  for_each = var.tier2_applications
  
  application_name    = each.key
  tier               = "tier2"
  resource_group_name = azurerm_resource_group.sire_primary.name
  
  vm_config = var.tier_configurations.tier2
  
  # Tier 2 applications share ingress resources
  shared_ingress_id = module.shared_ingress.application_gateway_id
  
  backup_config = {
    frequency = "PT4H"
    retention_days = 180
    geo_replicated = false
  }
  
  monitoring_config = {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.sire.id
    enable_advanced_monitoring = false
    alert_thresholds = {
      cpu_percentage = 80
      memory_percentage = 85
      disk_percentage = 90
    }
  }
  
  tags = merge(local.common_tags, {
    Tier = "2"
    Criticality = "Important"
  })
}

module "tier3_applications" {
  source = "./modules/application-tier"
  
  for_each = var.tier3_applications
  
  application_name    = each.key
  tier               = "tier3"
  resource_group_name = azurerm_resource_group.sire_primary.name
  
  vm_config = var.tier_configurations.tier3
  
  # Tier 3 applications use basic ingress
  shared_ingress_id = module.shared_ingress.basic_load_balancer_id
  
  backup_config = {
    frequency = "P1D"
    retention_days = 90
    geo_replicated = false
  }
  
  monitoring_config = {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.sire.id
    enable_advanced_monitoring = false
    alert_thresholds = {
      cpu_percentage = 90
      memory_percentage = 90
      disk_percentage = 95
    }
  }
  
  tags = merge(local.common_tags, {
    Tier = "3"
    Criticality = "Standard"
  })
}
```

## Post-Implementation Tasks

### 1. Documentation Updates
- Update network diagrams with actual IP addresses
- Document emergency procedures and contact information
- Create recovery runbooks and playbooks
- Update security procedures and access lists

### 2. Staff Training
- Conduct SIRE administrator training
- Create operator quick reference guides
- Schedule regular DR exercises
- Establish on-call procedures

### 3. Testing Schedule
- Monthly backup validation tests
- Quarterly recovery exercises
- Annual DR simulation
- Continuous security assessments

### 4. Monitoring Setup
- Configure alerting thresholds
- Set up dashboard monitoring
- Establish reporting procedures
- Create automated health checks

## Troubleshooting Common Issues

### Network Connectivity Issues
```bash
# Check route tables
az network route-table route list \
  --resource-group "rg-sire-primary-prod" \
  --route-table-name "rt-sire-management"

# Verify DNS resolution
az network private-dns record-set list \
  --resource-group "rg-sire-primary-prod" \
  --zone-name "privatelink.blob.core.windows.net"
```

### Backup Failures
```bash
# Check backup job status
az backup job list \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --status "Failed"

# Review backup alerts
az monitor activity-log list \
  --resource-group "rg-sire-primary-prod" \
  --max-events 50 \
  --offset 7d
```

### Access Issues
```powershell
# Check Microsoft Entra ID group membership
Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -Filter "DisplayName eq 'SIRE-Administrators'").ObjectId

# Verify RBAC assignments
Get-AzRoleAssignment -ResourceGroupName "rg-sire-primary-prod" | Format-Table
```

## Next Steps

1. Review [Operations Guide](./operations-guide.md) for day-to-day management
2. Implement monitoring procedures from [Monitoring Setup](./operations-guide.md#monitoring-setup)
3. Configure workload-specific components from [Workload Guides](./workloads/)
4. Schedule first DR test using [Testing Guide](./testing-guide.md)

## Support and Maintenance

- **Documentation Updates**: Review and update quarterly
- **Security Patches**: Apply monthly during maintenance windows
- **Infrastructure Reviews**: Conduct semi-annual assessments
- **Disaster Recovery Tests**: Execute quarterly exercises