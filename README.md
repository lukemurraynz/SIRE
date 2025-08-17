# Secure Isolated Recovery Environment (SIRE) for Microsoft Azure

A comprehensive guide to establishing and operating a Secure Isolated Recovery Environment (SIRE) in Microsoft Azure to prepare for and recover from ransomware attacks and cyber incidents.

## Overview

The Secure Isolated Recovery Environment (SIRE) is a specialized infrastructure pattern designed to maintain business continuity during and after cybersecurity incidents, particularly ransomware attacks. This documentation provides architectural guidance, implementation strategies, and operational procedures following Microsoft Azure Well-Architected Framework principles.

> **🌟 Same-Region SIRE Deployment - Primary Recommendation**
> 
> This guide now prioritizes **same-region SIRE deployment** as the primary architectural pattern, providing 20-40% cost savings while maintaining enterprise-grade security and compliance. Special guidance is included for regions without paired regions (3+0 regions) such as New Zealand North, Brazil South, and UAE Central.

## Documentation Structure

- **[Architecture Guide](./docs/architecture-guide.md)** - Technical architecture patterns and design principles
- **[Implementation Guide](./docs/implementation-guide.md)** - Step-by-step deployment procedures
- **[Security Guidelines](./docs/security-guidelines.md)** - Security controls and isolation mechanisms
- **[Ransomware Recovery Playbook](./docs/ransomware-recovery-playbook.md)** - **🚨 Emergency response and recovery procedures for active ransomware incidents**
- **[Workload Guides](./docs/workloads/)** - Specific guidance for different workload types
- **[Operations Guide](./docs/operations-guide.md)** - Day-to-day operations and monitoring
- **[Business Continuity Guide](./docs/business-continuity-guide.md)** - BC/DR strategies and procedures
- **[Testing Guide](./docs/testing-guide.md)** - Validation and testing procedures

## Key Concepts

### SIRE Principles

1. **Isolation**: Physical and logical separation from production environments
2. **Immutability**: Tamper-proof backup and recovery capabilities
3. **Accessibility**: Rapid activation and recovery procedures
4. **Verification**: Continuous validation of recovery capabilities
5. **Compliance**: Adherence to industry standards and regulations

### Recovery Phases

- **Prevention**: Proactive measures to prevent incidents
- **Detection**: Early identification of security threats
- **Containment**: Isolation and damage limitation
- **Recovery**: Restoration of business operations
- **Lessons Learned**: Post-incident analysis and improvement

## Getting Started

1. Review the [Architecture Guide](./docs/architecture-guide.md) to understand SIRE design patterns
2. Follow the [Implementation Guide](./docs/implementation-guide.md) for deployment
3. Configure security controls using the [Security Guidelines](./docs/security-guidelines.md)
4. Establish operations procedures from the [Operations Guide](./docs/operations-guide.md)
5. **🚨 In case of ransomware attack**: Use the [Ransomware Recovery Playbook](./docs/ransomware-recovery-playbook.md) for immediate response

> **Emergency Response**: If you are currently experiencing a ransomware attack, go directly to the [Ransomware Recovery Playbook](./docs/ransomware-recovery-playbook.md) for actionable guidance.
