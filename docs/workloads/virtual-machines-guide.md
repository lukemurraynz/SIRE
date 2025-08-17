# SIRE Virtual Machine Workload Guide

## Overview

This guide provides specific guidance for implementing Secure Isolated Recovery Environment (SIRE) capabilities for virtual machine workloads in Microsoft Azure. It covers backup strategies, recovery procedures, and security considerations for VMs in the SIRE environment.

## VM Backup Strategy

### Backup Architecture

```
Production VMs --> Azure Backup --> Recovery Services Vault --> SIRE Recovery
     |                |                      |                       |
     |                |                      |                       |
 App Servers     Backup Agent         Geo-redundant            Recovery VMs
 Database VMs    Policy Engine        Storage (GRS)            Test Environment
 Web Servers     Snapshot Mgmt        Immutable Vault          Forensic Analysis
```

### Backup Policies by VM Type

#### Critical Business Applications
```json
{
  "policyName": "SIRE-Critical-VM-Policy",
  "backupFrequency": "Daily",
  "backupTime": "02:00 UTC",
  "retentionPolicy": {
    "daily": {
      "retentionDuration": 90,
      "backupTime": "02:00"
    },
    "weekly": {
      "retentionDuration": 52,
      "backupDay": "Sunday"
    },
    "monthly": {
      "retentionDuration": 36,
      "backupWeek": "First",
      "backupDay": "Sunday"
    },
    "yearly": {
      "retentionDuration": 7,
      "backupMonth": "January",
      "backupWeek": "First",
      "backupDay": "Sunday"
    }
  },
  "features": {
    "instantRestore": true,
    "crossRegionRestore": true,
    "encryptionAtRest": true,
    "softDelete": true,
    "softDeleteRetentionPeriod": 14
  }
}
```

#### Standard Business Applications
```json
{
  "policyName": "SIRE-Standard-VM-Policy",
  "backupFrequency": "Daily",
  "backupTime": "03:00 UTC",
  "retentionPolicy": {
    "daily": {
      "retentionDuration": 30,
      "backupTime": "03:00"
    },
    "weekly": {
      "retentionDuration": 12,
      "backupDay": "Sunday"
    },
    "monthly": {
      "retentionDuration": 12,
      "backupWeek": "First",
      "backupDay": "Sunday"
    }
  }
}
```

#### Development and Test Systems
```json
{
  "policyName": "SIRE-DevTest-VM-Policy",
  "backupFrequency": "Weekly",
  "backupTime": "04:00 UTC",
  "retentionPolicy": {
    "weekly": {
      "retentionDuration": 4,
      "backupDay": "Saturday"
    }
  }
}
```

### Backup Configuration

#### Azure Backup Agent Installation
```powershell
# Install Azure Backup Agent on Windows VMs
$DownloadURL = "https://aka.ms/azurebackup_agent"
$AgentPath = "$env:TEMP\MARSAgentInstaller.exe"

# Download agent
Invoke-WebRequest -Uri $DownloadURL -OutFile $AgentPath

# Install agent silently
Start-Process -FilePath $AgentPath -ArgumentList "/q /nu" -Wait

# Register with Recovery Services Vault
$VaultCredentialsPath = "C:\temp\vault-credentials.VaultCredentials"
& "${env:ProgramFiles}\Microsoft Azure Recovery Services Agent\bin\wabadmin.exe" `
  START REGISTRATION `
  /VAULTCREDENTIALFILEPATH:$VaultCredentialsPath `
  /ENCRYPTIONPASSPHRASE:"$(Get-Content C:\temp\passphrase.txt)"
```

#### Backup Policy Assignment
```bash
# Enable backup for VM using Azure CLI
az backup protection enable-for-vm \
  --resource-group "rg-production" \
  --vault-name "rsv-sire-primary" \
  --vm "vm-app-server-01" \
  --policy-name "SIRE-Critical-VM-Policy"

# Verify backup configuration
az backup item show \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --container-name "IaasVMContainer;iaasvmcontainerv2;rg-production;vm-app-server-01" \
  --item-name "VM;iaasvmcontainerv2;rg-production;vm-app-server-01"
```

### Enhanced Backup Features

#### Application-Consistent Backups
```powershell
# Configure VSS settings for application consistency
$VSSSettings = @{
    "SQL Server" = @{
        ServiceName = "MSSQLSERVER"
        PreBackupScript = "C:\Scripts\sql-pre-backup.ps1"
        PostBackupScript = "C:\Scripts\sql-post-backup.ps1"
    }
    "IIS" = @{
        ServiceName = "W3SVC"
        PreBackupScript = "C:\Scripts\iis-pre-backup.ps1"
        PostBackupScript = "C:\Scripts\iis-post-backup.ps1"
    }
}

foreach ($App in $VSSSettings.Keys) {
    Write-Host "Configuring VSS for $App"
    # Configure application-specific VSS settings
}
```

#### Cross-Region Backup Verification
```bash
# Verify cross-region backup availability
az backup recoverypoint list \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --container-name "IaasVMContainer;iaasvmcontainerv2;rg-production;vm-app-server-01" \
  --item-name "VM;iaasvmcontainerv2;rg-production;vm-app-server-01" \
  --use-secondary-region
```

## VM Recovery Procedures

### Recovery Scenarios

#### Scenario 1: Full VM Recovery
```bash
#!/bin/bash
# Complete VM recovery to SIRE environment

VM_NAME="vm-app-server-01"
RECOVERY_RG="rg-sire-recovery"
RECOVERY_VNET="vnet-sire-primary"
RECOVERY_SUBNET="snet-recovery"

# Get latest recovery point
RECOVERY_POINT=$(az backup recoverypoint list \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --container-name "IaasVMContainer;iaasvmcontainerv2;rg-production;$VM_NAME" \
  --item-name "VM;iaasvmcontainerv2;rg-production;$VM_NAME" \
  --query "[0].name" -o tsv)

# Restore VM
az backup restore restore-disks \
  --resource-group "rg-sire-primary-prod" \
  --vault-name "rsv-sire-primary" \
  --container-name "IaasVMContainer;iaasvmcontainerv2;rg-production;$VM_NAME" \
  --item-name "VM;iaasvmcontainerv2;rg-production;$VM_NAME" \
  --rp-name "$RECOVERY_POINT" \
  --storage-account "stsirerecovery" \
  --target-resource-group "$RECOVERY_RG" \
  --target-subnet-name "$RECOVERY_SUBNET" \
  --target-vnet-name "$RECOVERY_VNET"

echo "VM recovery initiated. Monitor job status with:"
echo "az backup job list --resource-group rg-sire-primary-prod --vault-name rsv-sire-primary"
```

#### Scenario 2: Selective File Recovery
```powershell
# Mount recovery point for file-level recovery
$RecoveryJob = Start-AzRecoveryServicesBackupRestoreJob `
  -RecoveryPoint $RecoveryPoint `
  -TargetStorageAccountName "stsirerecovery" `
  -TargetFileShareName "file-recovery" `
  -RecoveryOption OriginalLocation

# Wait for mount to complete
do {
    Start-Sleep 30
    $JobStatus = Get-AzRecoveryServicesBackupJobDetail -Job $RecoveryJob
    Write-Host "Recovery job status: $($JobStatus.Status)"
} while ($JobStatus.Status -eq "InProgress")

if ($JobStatus.Status -eq "Completed") {
    Write-Host "Recovery point mounted. Access files at: $($JobStatus.Properties.TargetDetails.FilePath)"
    
    # Copy specific files
    $SourcePath = $JobStatus.Properties.TargetDetails.FilePath
    $TargetPath = "\\sire-recovery\shared\recovered-files"
    
    robocopy "$SourcePath\InetPub\wwwroot" "$TargetPath\wwwroot" /MIR /Z /W:5 /R:3
    robocopy "$SourcePath\Program Files\MyApp" "$TargetPath\MyApp" /MIR /Z /W:5 /R:3
    
    Write-Host "File recovery completed"
}
```

#### Scenario 3: Database Recovery
```sql
-- SQL Server database recovery from VM backup
-- Step 1: Restore VM with database files
-- Step 2: Extract database files
-- Step 3: Restore database

-- Mount database files from recovered VM
EXEC xp_cmdshell 'net use Z: \\sire-recovery\vm-sql-01\D$\Data'

-- Restore database from mounted files
RESTORE DATABASE [ProductionDB] 
FROM DISK = 'Z:\Backups\ProductionDB_Full.bak'
WITH 
    MOVE 'ProductionDB' TO 'D:\SIRE\Data\ProductionDB.mdf',
    MOVE 'ProductionDB_Log' TO 'D:\SIRE\Logs\ProductionDB.ldf',
    REPLACE,
    STATS = 10;

-- Verify database integrity
DBCC CHECKDB('ProductionDB') WITH NO_INFOMSGS;

-- Update database configuration for SIRE environment
ALTER DATABASE [ProductionDB] SET RECOVERY FULL;
ALTER DATABASE [ProductionDB] SET AUTO_CLOSE OFF;
ALTER DATABASE [ProductionDB] SET AUTO_SHRINK OFF;
```

### Automated Recovery Workflows

#### PowerShell Recovery Automation
```powershell
# SIRE VM Recovery Automation Script
param(
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    
    [Parameter(Mandatory = $true)]
    [string]$RecoveryType, # Full, Files, Database
    
    [Parameter(Mandatory = $false)]
    [string]$RecoveryPointDate,
    
    [Parameter(Mandatory = $false)]
    [string[]]$FilePaths
)

# Initialize Azure context
Connect-AzAccount -Identity
Set-AzContext -SubscriptionId (Get-AzContext).Subscription.Id

# Configuration
$VaultName = "rsv-sire-primary"
$VaultResourceGroup = "rg-sire-primary-prod"
$RecoveryResourceGroup = "rg-sire-recovery"
$StorageAccount = "stsirerecovery"

function Get-LatestRecoveryPoint {
    param([string]$VMName)
    
    $Container = "IaasVMContainer;iaasvmcontainerv2;rg-production;$VMName"
    $Item = "VM;iaasvmcontainerv2;rg-production;$VMName"
    
    $RecoveryPoints = Get-AzRecoveryServicesBackupRecoveryPoint `
        -Container $Container `
        -Item $Item `
        -VaultId (Get-AzRecoveryServicesVault -Name $VaultName -ResourceGroupName $VaultResourceGroup).ID
    
    if ($RecoveryPointDate) {
        return $RecoveryPoints | Where-Object { $_.RecoveryPointTime.Date -eq [DateTime]::Parse($RecoveryPointDate).Date } | Select-Object -First 1
    } else {
        return $RecoveryPoints | Select-Object -First 1
    }
}

function Start-VMRecovery {
    param(
        [string]$VMName,
        [object]$RecoveryPoint,
        [string]$Type
    )
    
    switch ($Type) {
        "Full" {
            Write-Host "Starting full VM recovery for $VMName"
            $RestoreJob = Restore-AzRecoveryServicesBackupItem `
                -RecoveryPoint $RecoveryPoint `
                -StorageAccountName $StorageAccount `
                -StorageAccountResourceGroupName $RecoveryResourceGroup `
                -TargetResourceGroupName $RecoveryResourceGroup
        }
        
        "Files" {
            Write-Host "Starting file recovery for $VMName"
            $RestoreJob = Restore-AzRecoveryServicesBackupItem `
                -RecoveryPoint $RecoveryPoint `
                -StorageAccountName $StorageAccount `
                -StorageAccountResourceGroupName $RecoveryResourceGroup `
                -FilePath $FilePaths
        }
        
        "Database" {
            Write-Host "Starting database recovery for $VMName"
            # Custom database recovery logic
            Invoke-DatabaseRecovery -VMName $VMName -RecoveryPoint $RecoveryPoint
        }
    }
    
    return $RestoreJob
}

# Main execution
try {
    Write-Host "SIRE VM Recovery initiated for $VMName (Type: $RecoveryType)"
    
    # Get recovery point
    $RecoveryPoint = Get-LatestRecoveryPoint -VMName $VMName
    if (-not $RecoveryPoint) {
        throw "No recovery point found for VM: $VMName"
    }
    
    Write-Host "Using recovery point from: $($RecoveryPoint.RecoveryPointTime)"
    
    # Start recovery
    $RestoreJob = Start-VMRecovery -VMName $VMName -RecoveryPoint $RecoveryPoint -Type $RecoveryType
    
    # Monitor progress
    do {
        Start-Sleep 60
        $JobStatus = Get-AzRecoveryServicesBackupJobDetail -Job $RestoreJob
        Write-Host "Recovery progress: $($JobStatus.Status) - $($JobStatus.PercentComplete)%"
    } while ($JobStatus.Status -eq "InProgress")
    
    if ($JobStatus.Status -eq "Completed") {
        Write-Host "✓ Recovery completed successfully for $VMName" -ForegroundColor Green
        
        # Post-recovery actions
        if ($RecoveryType -eq "Full") {
            Invoke-PostRecoveryConfiguration -VMName "$VMName-SIRE"
        }
    } else {
        throw "Recovery failed with status: $($JobStatus.Status)"
    }
}
catch {
    Write-Error "Recovery failed: $($_.Exception.Message)"
    # Send alert to operations team
    Send-SIREAlert -Type "RecoveryFailure" -VMName $VMName -Error $_.Exception.Message
}
```

### Recovery Validation

#### Health Check Scripts
```powershell
# VM Recovery Health Check
function Test-VMRecoveryHealth {
    param(
        [string]$VMName,
        [string]$ResourceGroup = "rg-sire-recovery"
    )
    
    $HealthResults = @()
    
    # Check VM status
    $VM = Get-AzVM -ResourceGroupName $ResourceGroup -Name $VMName -Status
    $HealthResults += @{
        Component = "VM Status"
        Status = $VM.Statuses | Where-Object { $_.Code -like "PowerState/*" } | Select-Object -ExpandProperty DisplayStatus
        Expected = "VM running"
    }
    
    # Check network connectivity
    $NetworkTest = Test-NetConnection -ComputerName $VMName -Port 3389 -InformationLevel Quiet
    $HealthResults += @{
        Component = "Network Connectivity"
        Status = if ($NetworkTest) { "Connected" } else { "Failed" }
        Expected = "Connected"
    }
    
    # Check disk health
    $DiskCheck = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroup -VMName $VMName -CommandId "RunPowerShellScript" -ScriptString "Get-Disk | Select-Object Number, HealthStatus"
    $HealthResults += @{
        Component = "Disk Health"
        Status = "Checked via Run Command"
        Expected = "Healthy"
    }
    
    # Check services
    $ServiceCheck = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroup -VMName $VMName -CommandId "RunPowerShellScript" -ScriptString "Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic' } | Select-Object Name, Status"
    $HealthResults += @{
        Component = "Critical Services"
        Status = "Checked via Run Command"
        Expected = "All automatic services running"
    }
    
    return $HealthResults
}

# Application-specific health checks
function Test-ApplicationHealth {
    param(
        [string]$VMName,
        [string]$ApplicationType
    )
    
    switch ($ApplicationType) {
        "WebServer" {
            $WebTest = Test-NetConnection -ComputerName $VMName -Port 80
            return @{
                Component = "Web Server"
                Status = if ($WebTest.TcpTestSucceeded) { "Responding" } else { "Failed" }
                Port = 80
            }
        }
        
        "DatabaseServer" {
            $SQLTest = Test-NetConnection -ComputerName $VMName -Port 1433
            return @{
                Component = "SQL Server"
                Status = if ($SQLTest.TcpTestSucceeded) { "Responding" } else { "Failed" }
                Port = 1433
            }
        }
        
        "FileServer" {
            $FileTest = Test-NetConnection -ComputerName $VMName -Port 445
            return @{
                Component = "File Server"
                Status = if ($FileTest.TcpTestSucceeded) { "Responding" } else { "Failed" }
                Port = 445
            }
        }
    }
}
```

## Security Hardening for Recovered VMs

### Security Baseline Configuration

#### Windows Security Hardening
```powershell
# Windows security hardening for SIRE VMs
function Set-SIRESecurityBaseline {
    param([string]$VMName)
    
    # Disable unnecessary services
    $ServicesToDisable = @(
        "Fax",
        "TelNet",
        "RemoteRegistry",
        "SSDPSRV",
        "upnphost"
    )
    
    foreach ($Service in $ServicesToDisable) {
        Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
    }
    
    # Configure Windows Firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    
    # Enable audit policies
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable
    
    # Configure password policy
    net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5
    
    # Enable Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -SubmitSamplesConsent 2
    Set-MpPreference -MAPSReporting 2
    
    Write-Host "Security baseline applied to $VMName"
}
```

#### Linux Security Hardening
```bash
#!/bin/bash
# Linux security hardening for SIRE VMs

VM_NAME=$1

# Update system packages
sudo apt update && sudo apt upgrade -y

# Configure SSH security
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Configure firewall
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow from 10.100.0.0/16

# Install and configure fail2ban
sudo apt install fail2ban -y
sudo cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Configure automatic updates
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Set up log monitoring
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd

echo "Security baseline applied to $VM_NAME"
```

### Network Isolation in SIRE

#### Network Security Group Configuration
```json
{
  "securityRules": [
    {
      "name": "Allow-SIRE-Management",
      "properties": {
        "priority": 100,
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "Tcp",
        "sourcePortRange": "*",
        "destinationPortRange": "3389",
        "sourceAddressPrefix": "10.100.1.0/24",
        "destinationAddressPrefix": "10.100.2.0/24"
      }
    },
    {
      "name": "Allow-Internal-Communication",
      "properties": {
        "priority": 200,
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "*",
        "sourcePortRange": "*",
        "destinationPortRange": "*",
        "sourceAddressPrefix": "10.100.2.0/24",
        "destinationAddressPrefix": "10.100.2.0/24"
      }
    },
    {
      "name": "Deny-Internet-Access",
      "properties": {
        "priority": 4000,
        "access": "Deny",
        "direction": "Outbound",
        "protocol": "*",
        "sourcePortRange": "*",
        "destinationPortRange": "*",
        "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "Internet"
      }
    },
    {
      "name": "Deny-All-Other-Inbound",
      "properties": {
        "priority": 4096,
        "access": "Deny",
        "direction": "Inbound",
        "protocol": "*",
        "sourcePortRange": "*",
        "destinationPortRange": "*",
        "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "*"
      }
    }
  ]
}
```

## Monitoring and Alerting

### VM Performance Monitoring
```powershell
# Configure Azure Monitor for SIRE VMs
function Set-SIREMonitoring {
    param(
        [string]$VMName,
        [string]$ResourceGroup,
        [string]$WorkspaceName
    )
    
    # Install Azure Monitor Agent
    $Extension = Set-AzVMExtension `
        -ResourceGroupName $ResourceGroup `
        -VMName $VMName `
        -Name "AzureMonitorWindowsAgent" `
        -Publisher "Microsoft.Azure.Monitor" `
        -ExtensionType "AzureMonitorWindowsAgent" `
        -TypeHandlerVersion "1.0" `
        -EnableAutomaticUpgrade $true
    
    # Configure data collection rules
    $DataCollectionRule = @{
        location = "East US 2"
        properties = @{
            dataSources = @{
                performanceCounters = @(
                    @{
                        streams = @("Microsoft-Perf")
                        scheduledTransferPeriod = "PT1M"
                        samplingFrequencyInSeconds = 60
                        counterSpecifiers = @(
                            "\\Processor(_Total)\\% Processor Time",
                            "\\Memory\\Available MBytes",
                            "\\LogicalDisk(_Total)\\Disk Reads/sec",
                            "\\LogicalDisk(_Total)\\Disk Writes/sec"
                        )
                    }
                )
                windowsEventLogs = @(
                    @{
                        streams = @("Microsoft-WindowsEvent")
                        xPathQueries = @(
                            "Security!*[System[(Level=1 or Level=2 or Level=3)]]",
                            "System!*[System[(Level=1 or Level=2 or Level=3)]]",
                            "Application!*[System[(Level=1 or Level=2 or Level=3)]]"
                        )
                    }
                )
            }
            destinations = @{
                logAnalytics = @(
                    @{
                        workspaceResourceId = "/subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
                        name = "law-sire-primary"
                    }
                )
            }
            dataFlows = @(
                @{
                    streams = @("Microsoft-Perf", "Microsoft-WindowsEvent")
                    destinations = @("law-sire-primary")
                }
            )
        }
    }
    
    Write-Host "Monitoring configured for $VMName"
}
```

### Custom Alerts for SIRE VMs
```json
{
  "alertRules": [
    {
      "name": "SIRE-VM-High-CPU",
      "description": "Alert when SIRE VM CPU usage exceeds 80%",
      "severity": 2,
      "criteria": {
        "allOf": [
          {
            "metricName": "Percentage CPU",
            "operator": "GreaterThan",
            "threshold": 80,
            "timeAggregation": "Average"
          }
        ]
      },
      "windowSize": "PT5M",
      "evaluationFrequency": "PT1M",
      "actions": [
        {
          "actionGroupId": "/subscriptions/{subscription-id}/resourceGroups/rg-sire-primary-prod/providers/Microsoft.Insights/actionGroups/sire-alerts"
        }
      ]
    },
    {
      "name": "SIRE-VM-Disk-Space-Low",
      "description": "Alert when SIRE VM disk space is below 10%",
      "severity": 1,
      "criteria": {
        "allOf": [
          {
            "metricName": "OS Disk Queue Depth",
            "operator": "GreaterThan",
            "threshold": 90,
            "timeAggregation": "Average"
          }
        ]
      }
    },
    {
      "name": "SIRE-VM-Unexpected-Restart",
      "description": "Alert when SIRE VM restarts unexpectedly",
      "severity": 1,
      "query": "Event | where Computer contains 'sire' and EventID == 1074 | where TimeGenerated > ago(1h)",
      "actions": [
        {
          "actionGroupId": "/subscriptions/{subscription-id}/resourceGroups/rg-sire-primary-prod/providers/Microsoft.Insights/actionGroups/sire-critical-alerts"
        }
      ]
    }
  ]
}
```

## Best Practices and Recommendations

### VM Design Principles for SIRE

#### 1. Stateless Application Design
- Separate application code from configuration
- Store session data externally (Redis, database)
- Use immutable infrastructure patterns
- Implement health check endpoints

#### 2. Resource Right-Sizing
- Monitor baseline performance requirements
- Use burst-capable VM sizes for variable workloads
- Implement auto-scaling where appropriate
- Regular capacity planning reviews

#### 3. High Availability Configuration
```powershell
# Create availability set for SIRE VMs
$AvailabilitySet = New-AzAvailabilitySet `
    -ResourceGroupName "rg-sire-recovery" `
    -Name "as-sire-recovery" `
    -Location "East US 2" `
    -PlatformFaultDomainCount 2 `
    -PlatformUpdateDomainCount 5 `
    -Sku "Aligned"

# Deploy VMs in availability set
$VMConfig = New-AzVMConfig `
    -VMName "vm-sire-app-01" `
    -VMSize "Standard_D4s_v4" `
    -AvailabilitySetId $AvailabilitySet.Id
```

### Backup Optimization

#### Selective Disk Backup
```bash
# Configure selective disk backup for VMs with multiple disks
az backup protection enable-for-vm \
  --resource-group "rg-production" \
  --vault-name "rsv-sire-primary" \
  --vm "vm-app-server-01" \
  --policy-name "SIRE-Critical-VM-Policy" \
  --disk-list-setting "include" \
  --diskslist "disk-os" "disk-data-01"
```

#### Backup Performance Tuning
```json
{
  "backupOptimization": {
    "excludeFiles": [
      "*.tmp",
      "*.log",
      "*.cache",
      "C:\\Windows\\Temp\\*",
      "C:\\Users\\*\\AppData\\Local\\Temp\\*"
    ],
    "compressionLevel": "high",
    "transferSpeed": "unlimited",
    "scheduleOptimization": {
      "lowActivityHours": "02:00-06:00",
      "distributedScheduling": true,
      "staggerBackups": "15minutes"
    }
  }
}
```

### Recovery Testing

#### Automated Recovery Testing
```powershell
# Quarterly recovery test automation
function Start-SIRERecoveryTest {
    param(
        [string]$TestType = "NonProduction", # NonProduction, Production
        [string[]]$TestVMs,
        [string]$TestResourceGroup = "rg-sire-test"
    )
    
    $TestResults = @()
    
    foreach ($VM in $TestVMs) {
        try {
            Write-Host "Starting recovery test for $VM"
            
            # Create test recovery
            $RecoveryJob = Start-TestVMRecovery -VMName $VM -TargetResourceGroup $TestResourceGroup
            
            # Wait for completion
            Wait-AzRecoveryServicesBackupJob -Job $RecoveryJob
            
            # Validate recovery
            $ValidationResult = Test-VMRecoveryHealth -VMName "$VM-test" -ResourceGroup $TestResourceGroup
            
            $TestResults += @{
                VM = $VM
                Status = "Success"
                RecoveryTime = (Get-Date) - $RecoveryJob.StartTime
                ValidationResults = $ValidationResult
            }
            
            # Cleanup test resources if successful
            if ($TestType -eq "NonProduction") {
                Remove-AzVM -ResourceGroupName $TestResourceGroup -Name "$VM-test" -Force
            }
        }
        catch {
            $TestResults += @{
                VM = $VM
                Status = "Failed"
                Error = $_.Exception.Message
            }
        }
    }
    
    # Generate test report
    $TestResults | Export-Csv "SIRE-Recovery-Test-$(Get-Date -Format 'yyyyMMdd').csv"
    Send-TestReport -Results $TestResults
}
```

## Troubleshooting Guide

### Common Recovery Issues

#### Issue 1: Backup Agent Communication Failure
```powershell
# Diagnose and fix backup agent issues
function Repair-BackupAgent {
    param([string]$VMName)
    
    # Check agent installation
    $Agent = Get-Service "obengine" -ErrorAction SilentlyContinue
    if (-not $Agent) {
        Write-Host "Backup agent not installed, installing..."
        # Reinstall agent logic
    }
    
    # Check network connectivity
    $ConnTest = Test-NetConnection -ComputerName "pod01-rec2.geo.recovery.windowsazure.com" -Port 443
    if (-not $ConnTest.TcpTestSucceeded) {
        Write-Host "Network connectivity issue detected"
        # Network troubleshooting logic
    }
    
    # Check vault registration
    $RegStatus = & "${env:ProgramFiles}\Microsoft Azure Recovery Services Agent\bin\wabadmin.exe" GET CONFIG
    if ($RegStatus -notlike "*Vault*") {
        Write-Host "Vault registration issue, re-registering..."
        # Re-registration logic
    }
}
```

#### Issue 2: VM Recovery Failure
```bash
# Troubleshoot VM recovery failures
#!/bin/bash

check_recovery_prerequisites() {
    local vm_name=$1
    
    echo "Checking recovery prerequisites for $vm_name"
    
    # Check Recovery Services Vault
    vault_status=$(az backup vault show --name "rsv-sire-primary" --resource-group "rg-sire-primary-prod" --query "properties.provisioningState" -o tsv)
    if [ "$vault_status" != "Succeeded" ]; then
        echo "ERROR: Recovery Services Vault not ready"
        return 1
    fi
    
    # Check storage account
    storage_status=$(az storage account show --name "stsirerecovery" --resource-group "rg-sire-recovery" --query "provisioningState" -o tsv)
    if [ "$storage_status" != "Succeeded" ]; then
        echo "ERROR: Storage account not ready"
        return 1
    fi
    
    # Check network resources
    vnet_status=$(az network vnet show --name "vnet-sire-primary" --resource-group "rg-sire-primary-prod" --query "provisioningState" -o tsv)
    if [ "$vnet_status" != "Succeeded" ]; then
        echo "ERROR: Virtual network not ready"
        return 1
    fi
    
    echo "All prerequisites checked successfully"
    return 0
}

# Main troubleshooting function
troubleshoot_recovery() {
    local vm_name=$1
    
    check_recovery_prerequisites "$vm_name"
    
    # Check recovery points
    recovery_points=$(az backup recoverypoint list \
        --resource-group "rg-sire-primary-prod" \
        --vault-name "rsv-sire-primary" \
        --container-name "IaasVMContainer;iaasvmcontainerv2;rg-production;$vm_name" \
        --item-name "VM;iaasvmcontainerv2;rg-production;$vm_name" \
        --query "length(@)")
    
    if [ "$recovery_points" -eq 0 ]; then
        echo "ERROR: No recovery points found for $vm_name"
        return 1
    fi
    
    echo "Found $recovery_points recovery points for $vm_name"
}
```

## Cost Optimization

### VM Cost Management for SIRE

#### Reserved Instances Strategy
```powershell
# Calculate reserved instance savings for SIRE VMs
function Get-SIREReservedInstanceRecommendations {
    param(
        [string]$SubscriptionId,
        [int]$LookbackDays = 30
    )
    
    # Get VM usage data
    $VMs = Get-AzVM | Where-Object { $_.Tags.Environment -eq "SIRE" }
    
    $Recommendations = @()
    foreach ($VM in $VMs) {
        $Usage = Get-AzConsumptionUsageDetail -StartDate (Get-Date).AddDays(-$LookbackDays) -EndDate (Get-Date) | 
                 Where-Object { $_.InstanceName -eq $VM.Name }
        
        if ($Usage) {
            $MonthlyHours = ($Usage | Measure-Object -Property UsageQuantity -Sum).Sum
            $RecommendedRI = if ($MonthlyHours -gt 540) { "1-Year" } elseif ($MonthlyHours -gt 360) { "3-Year" } else { "Pay-as-Go" }
            
            $Recommendations += @{
                VMName = $VM.Name
                VMSize = $VM.HardwareProfile.VmSize
                MonthlyHours = $MonthlyHours
                RecommendedRI = $RecommendedRI
                EstimatedSavings = Calculate-RISavings -VMSize $VM.HardwareProfile.VmSize -Hours $MonthlyHours
            }
        }
    }
    
    return $Recommendations
}
```

#### Automated VM Scheduling
```json
{
  "vmScheduling": {
    "developmentVMs": {
      "schedule": "Monday-Friday 8AM-6PM",
      "timezone": "Eastern Standard Time",
      "startAction": "start",
      "stopAction": "deallocate"
    },
    "testingVMs": {
      "schedule": "Monday-Sunday 6AM-10PM",
      "timezone": "Eastern Standard Time",
      "weekendShutdown": true
    },
    "productionRecoveryVMs": {
      "schedule": "24x7",
      "highAvailability": true,
      "autoScaling": {
        "enabled": true,
        "minInstances": 2,
        "maxInstances": 10,
        "scaleUpThreshold": 70,
        "scaleDownThreshold": 30
      }
    }
  }
}
```

## Next Steps

1. Review [Container Apps Workload Guide](./container-apps-guide.md) for containerized applications
2. Implement database-specific procedures from [Database Workload Guide](./database-guide.md)
3. Configure monitoring using [Operations Guide](../operations-guide.md)
4. Schedule recovery testing using [Testing Guide](../testing-guide.md)