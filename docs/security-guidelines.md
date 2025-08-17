# SIRE Security Guidelines

## Overview

This document provides comprehensive security guidelines for implementing and operating a Secure Isolated Recovery Environment (SIRE) in Microsoft Azure. These guidelines focus on protecting against ransomware attacks and ensuring secure recovery operations.

📊 **Visual Reference:** [Zero Trust Architecture Diagram](diagrams/06-zero-trust-architecture.drawio) and [Network Security Zones](diagrams/02-sire-network-topology.drawio)

## Security Framework

### Zero Trust Principles

![Zero Trust Architecture](diagrams/06-zero-trust-architecture.drawio)

*Professional diagram showing comprehensive Zero Trust security model implementation*

The SIRE security model is built on Zero Trust principles:

1. **Verify explicitly**: Always authenticate and authorize based on all available data points
2. **Use least privilege access**: Limit user access with Just-In-Time and Just-Enough-Access
3. **Assume breach**: Minimize blast radius and segment access

### Defense in Depth Strategy

![Defense in Depth](diagrams/08-defense-in-depth.drawio)

*Professional diagram showcasing Azure native security controls in a layered defense architecture*

The SIRE security framework implements a comprehensive defense-in-depth strategy using Azure native security services. This approach provides multiple layers of protection, ensuring that if one layer is compromised, additional layers continue to protect the environment.

#### Layer 1: Network Security
- Network segmentation and isolation
- Firewall and intrusion prevention
- DDoS protection and traffic filtering

#### Layer 2: Identity and Access
- Multi-factor authentication (MFA)
- Privileged access management (PAM)
- Regular access reviews

#### Layer 3: Application Security
- Secure coding practices
- Application firewalls
- Container security

#### Layer 4: Data Protection
- Encryption at rest and in transit
- Data classification and handling
- Immutable backup protection

## Network Security

### Network Isolation

![Network Security Zones](diagrams/02-sire-network-topology.drawio)

*Detailed network topology showing security zones, traffic flows, and protection mechanisms*

#### Virtual Network Design
```
SIRE Virtual Network (10.100.0.0/16)
├── DMZ Subnet (10.100.0.0/24)
│   ├── Azure Firewall
│   └── Application Gateway
├── Management Subnet (10.100.1.0/24)
│   ├── Jump servers
│   └── Administrative tools
├── Recovery Subnet (10.100.2.0/24)
│   ├── Recovery VMs
│   └── Test environments
├── Forensics Subnet (10.100.3.0/24)
│   ├── Analysis tools
│   └── Evidence storage
└── Backup Subnet (10.100.4.0/24)
    ├── Backup services
    └── Storage gateways
```

#### Network Security Groups (NSGs)

**Management Subnet NSG Rules**:
```json
{
  "securityRules": [
    {
      "name": "Allow-RDP-from-Bastion",
      "properties": {
        "priority": 100,
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "Tcp",
        "sourcePortRange": "*",
        "destinationPortRange": "3389",
        "sourceAddressPrefix": "10.100.0.0/24",
        "destinationAddressPrefix": "10.100.1.0/24"
      }
    },
    {
      "name": "Deny-All-Inbound",
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

### Azure Firewall Configuration

#### Application Rules
- Allow necessary Azure services (Microsoft Entra ID, Key Vault, Storage)
- Block all other internet access
- Log all traffic for audit purposes

#### Network Rules
- Inter-subnet communication controls
- DNS resolution restrictions
- Time-based access controls

### Private Endpoints

Implement private endpoints for:
- Azure Storage accounts
- Azure Key Vault
- Azure SQL databases
- Recovery Services vaults

## Identity and Access Management

> **🎯 Primary Focus: Same-Tenant Identity Isolation**
> 
> This section emphasizes same-tenant RBAC boundaries as the primary security model for SIRE deployments, providing enterprise-grade isolation within your existing Microsoft Entra ID tenant.

### Same-Tenant Identity Isolation Strategy

**Core Security Principles:**
- **Strict RBAC Boundaries**: Custom roles scoped exclusively to SIRE resources
- **Conditional Access Controls**: SIRE-specific policies with enhanced requirements
- **Privileged Access Management**: PIM and JIT for all administrative functions
- **Identity Segregation**: Dedicated service principals and managed identities
- **Emergency Access Controls**: Break-glass accounts with SIRE-only permissions

**Security Equivalence Validation:**
The same-tenant approach with proper RBAC boundaries provides equivalent security to separate tenant deployment while maintaining operational efficiency and cost optimization.

### Microsoft Entra ID Security

#### Conditional Access Policies

**Primary Policy: Same-Tenant SIRE Access Control**:
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
      "includeLocations": ["SIRE-Network-Location"],
      "excludeLocations": ["Production-Network-Locations"]
    },
    "platforms": {
      "includePlatforms": ["windows", "macOS"],
      "excludePlatforms": ["iOS", "android"]
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
    "signInFrequency": {
      "value": 4,
      "type": "hours",
      "isEnabled": true
    },
    "applicationEnforcedRestrictions": {
      "isEnabled": true
    }
  }
}
```

**Complementary Policy: SIRE Resource Protection**:
```json
{
  "displayName": "SIRE-Resource-Protection-Policy",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeUsers": ["All"],
      "excludeGroups": ["SIRE-Administrators", "SIRE-Operators", "SIRE-Forensics"]
    },
    "applications": {
      "includeApplications": ["All cloud apps"]
    },
    "resources": {
      "includeApplications": ["SIRE-ResourceGroup-*"]
    }
  },
  "grantControls": {
    "builtInControls": ["block"]
  }
}
```

#### Privileged Identity Management (PIM)

**Emergency Access Roles**:
- **SIRE Administrator**: Full administrative access during incidents
- **Recovery Operator**: Limited access for recovery operations
- **Forensics Analyst**: Read-only access for investigation

**PIM Configuration**:
```json
{
  "roleDefinition": "SIRE-Administrator",
  "settings": {
    "activationDuration": "PT4H",
    "approvalRequired": true,
    "approvers": ["Security-Team", "IT-Director"],
    "activationEmail": true,
    "activationMFA": true
  }
}
```

### Emergency Access Accounts

#### Break-Glass Accounts
- Two dedicated emergency accounts
- Complex passwords stored offline
- Regular validation procedures
- Excluded from conditional access policies

#### Account Management
```powershell
# Emergency account creation
$EmergencyAccount = @{
    DisplayName = "Emergency-SIRE-Admin-01"
    UserPrincipalName = "emergency-sire-admin-01@contoso.com"
    AccountEnabled = $true
    PasswordPolicies = "DisablePasswordExpiration"
    UsageLocation = "US"
}
```

## Data Protection

### Backup Security

#### Azure Backup Configuration

**Security Features**:
- Immutable vault settings
- Soft delete protection (14-90 days)
- Multi-user authorization (MUA)
- Private endpoint connectivity

**Backup Policy Example**:
```json
{
  "name": "SIRE-CriticalWorkloads-Policy",
  "properties": {
    "backupManagementType": "AzureIaasVM",
    "schedulePolicy": {
      "schedulePolicyType": "SimpleSchedulePolicy",
      "scheduleRunFrequency": "Daily",
      "scheduleRunTimes": ["2023-01-01T02:00:00.000Z"],
      "scheduleWeeklyFrequency": 0
    },
    "retentionPolicy": {
      "retentionPolicyType": "LongTermRetentionPolicy",
      "dailySchedule": {
        "retentionTimes": ["2023-01-01T02:00:00.000Z"],
        "retentionDuration": {
          "count": 30,
          "durationType": "Days"
        }
      },
      "weeklySchedule": {
        "retentionTimes": ["2023-01-01T02:00:00.000Z"],
        "retentionDuration": {
          "count": 12,
          "durationType": "Weeks"
        },
        "daysOfTheWeek": ["Sunday"]
      },
      "monthlySchedule": {
        "retentionTimes": ["2023-01-01T02:00:00.000Z"],
        "retentionDuration": {
          "count": 12,
          "durationType": "Months"
        },
        "retentionScheduleFormatType": "Weekly",
        "retentionScheduleWeekly": {
          "daysOfTheWeek": ["Sunday"],
          "weeksOfTheMonth": ["First"]
        }
      }
    }
  }
}
```

#### Immutable Storage

**WORM (Write Once, Read Many) Configuration**:
```json
{
  "immutabilityPolicy": {
    "properties": {
      "immutabilityPeriodSinceCreationInDays": 2555,
      "allowProtectedAppendWrites": false,
      "state": "Locked"
    }
  },
  "legalHold": {
    "hasLegalHold": true,
    "tags": [
      "Ransomware-Investigation-2024",
      "Legal-Hold-Active"
    ]
  }
}
```

### Encryption

#### Encryption at Rest
- Azure Storage Service Encryption (SSE)
- Customer-managed keys (CMK) in Azure Key Vault
- Database Transparent Data Encryption (TDE)

#### Encryption in Transit
- TLS 1.2 minimum for all communications
- IPSec VPN for site-to-site connections
- Azure Front Door SSL termination

#### Key Management
```json
{
  "keyVault": {
    "name": "SIRE-KeyVault-Primary",
    "properties": {
      "enableSoftDelete": true,
      "softDeleteRetentionInDays": 90,
      "enablePurgeProtection": true,
      "networkAcls": {
        "defaultAction": "Deny",
        "virtualNetworkRules": [
          {
            "id": "/subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}"
          }
        ]
      }
    }
  }
}
```

## Threat Detection and Response

### Microsoft Defender for Cloud

#### Security Recommendations
- Enable Microsoft Defender for all services
- Configure security alerts and notifications
- Implement automated response actions

#### Defender Plans Configuration
```json
{
  "defenderPlans": [
    {
      "resourceType": "VirtualMachines",
      "pricingTier": "Standard",
      "subPlan": "P2"
    },
    {
      "resourceType": "Storage",
      "pricingTier": "Standard"
    },
    {
      "resourceType": "KeyVaults",
      "pricingTier": "Standard"
    },
    {
      "resourceType": "Containers",
      "pricingTier": "Standard"
    }
  ]
}
```

### Microsoft Sentinel

#### Data Connectors
- Azure Activity logs
- Microsoft Entra ID audit logs
- Security events from VMs
- Azure Firewall logs
- Azure Storage logs

#### Analytics Rules

**Ransomware Detection Rule**:
```json
{
  "displayName": "Potential Ransomware Activity Detected",
  "description": "Detects potential ransomware indicators in file operations",
  "severity": "High",
  "query": "SecurityEvent\n| where EventID == 4663\n| where ObjectName contains \".encrypted\" or ObjectName contains \".locked\"\n| summarize count() by Computer, Account\n| where count_ > 100",
  "queryFrequency": "PT5M",
  "queryPeriod": "PT10M",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 0
}
```

#### Automation Rules
- Automatic incident assignment
- Notification to security team
- Initial containment actions

### Security Monitoring

#### Key Performance Indicators (KPIs)
- Mean Time to Detection (MTTD)
- Mean Time to Response (MTTR)
- False positive rate
- Security incident count

#### Monitoring Queries
```kusto
// Failed authentication attempts
SigninLogs
| where ResultType != "0"
| where UserPrincipalName contains "sire"
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailedAttempts > 5

// Suspicious file operations
SecurityEvent
| where EventID in (4663, 4656)
| where ObjectName contains ".encrypted" or ObjectName contains ".locked"
| extend FileName = extract(@"([^\\]*)$", 1, ObjectName)
| summarize FileCount = dcount(FileName) by Computer, Account, bin(TimeGenerated, 1h)
| where FileCount > 50
```

## Container Security

### Azure Container Apps Security

#### Container Image Security
- Use minimal base images
- Regular vulnerability scanning
- Signed container images
- Private container registries

#### Runtime Security
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sire-recovery-service
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: recovery-service
        image: sireregistry.azurecr.io/recovery-service:v1.0.0
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
```

### Kubernetes Security (AKS)

#### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sire-isolation-policy
  namespace: sire-recovery
spec:
  podSelector:
    matchLabels:
      app: sire-recovery
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: sire-management
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: sire-storage
    ports:
    - protocol: TCP
      port: 443
```

## Compliance and Governance

### Azure Policy Implementation

#### SIRE Security Baseline Policies
```json
{
  "policyDefinitions": [
    {
      "displayName": "SIRE-Require-MFA",
      "description": "Requires MFA for all SIRE resource access",
      "policyRule": {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Compute/virtualMachines"
            },
            {
              "field": "tags['Environment']",
              "equals": "SIRE"
            }
          ]
        },
        "then": {
          "effect": "deployIfNotExists",
          "details": {
            "type": "Microsoft.AAD/conditionalAccess",
            "existenceCondition": {
              "field": "properties.grantControls.builtInControls",
              "contains": "mfa"
            }
          }
        }
      }
    }
  ]
}
```

#### Compliance Monitoring
- Regular compliance assessments
- Automated remediation actions
- Exception management processes

### Audit and Logging

#### Audit Requirements
- All administrative actions
- Data access and modifications
- Security configuration changes
- Recovery operations

#### Log Retention
- Security logs: 7 years
- Audit logs: 3 years
- Operational logs: 1 year
- Debug logs: 30 days

## Incident Response Integration

### Security Incident Workflow

1. **Detection**: Automated alerts and monitoring
2. **Analysis**: Initial assessment and classification
3. **Containment**: Isolation and damage limitation
4. **Eradication**: Threat removal and system cleaning
5. **Recovery**: Service restoration using SIRE
6. **Lessons Learned**: Post-incident review

### SIRE Activation Triggers

#### Automatic Triggers
- Ransomware indicators detected
- Multiple system compromises
- Critical service unavailability
- Data exfiltration alerts

#### Manual Triggers
- Security team assessment
- Executive decision
- Regulatory requirement
- Customer request

## Testing and Validation

### Security Testing

#### Penetration Testing
- Annual third-party assessments
- Quarterly internal testing
- Red team exercises
- Social engineering tests

#### Vulnerability Management
- Weekly vulnerability scans
- Monthly patch management
- Continuous monitoring
- Risk-based prioritization

### Recovery Testing

#### Testing Scenarios
- Ransomware simulation
- Data center failure
- Personnel unavailability
- Supply chain attack

#### Testing Metrics
- Recovery Time Objective (RTO): 4 hours
- Recovery Point Objective (RPO): 15 minutes
- Test success rate: 95%
- Documentation accuracy: 100%

## Security Controls Matrix

| Control Category | Azure Service | Implementation | Monitoring |
|------------------|---------------|----------------|------------|
| Identity & Access | Microsoft Entra ID + PIM | MFA, RBAC, Conditional Access | Sign-in logs, Audit logs |
| Network Security | Azure Firewall + NSGs | Segmentation, Private endpoints | Network logs, Flow logs |
| Data Protection | Azure Backup + Storage | Encryption, Immutable storage | Backup reports, Access logs |
| Threat Detection | Defender + Sentinel | SIEM, Analytics rules | Security alerts, Incidents |
| Compliance | Azure Policy | Governance controls | Compliance dashboard |

## Next Steps

1. Review [Implementation Guide](./implementation-guide.md) for deployment procedures
2. Configure monitoring using [Operations Guide](./operations-guide.md)
3. Establish testing procedures from [Testing Guide](./testing-guide.md)
4. Review workload-specific guides in [Workloads](./workloads/) directory