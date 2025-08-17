# SIRE Container Apps Workload Guide

## Overview

This guide provides specific guidance for implementing Secure Isolated Recovery Environment (SIRE) capabilities for Azure Container Apps workloads. It covers backup strategies, recovery procedures, and security considerations for containerized applications in the SIRE environment.

## Container Apps in SIRE Architecture

### Architecture Overview

```
Production Container Apps --> Container Registry --> SIRE Recovery Environment
           |                         |                         |
           |                         |                         |
    App Containers              Signed Images             Recovery Containers
    Config Maps                 Vulnerability Scan         Isolated Network
    Secrets/Env Vars           Backup Metadata             Forensic Analysis
    Persistent Volumes         Immutable Storage           Testing Environment
```

### SIRE-Specific Container Apps Design

#### Network Isolation
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: sire-recovery
  labels:
    environment: "sire"
    isolation: "maximum"
spec:
  finalizers:
  - kubernetes

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sire-isolation-policy
  namespace: sire-recovery
spec:
  podSelector: {}
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
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

## Container Backup Strategies

### Application Data Backup

#### Persistent Volume Backup
```yaml
# Azure Container Apps with persistent storage
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sire-app-deployment
  namespace: sire-recovery
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sire-recovery-app
  template:
    metadata:
      labels:
        app: sire-recovery-app
    spec:
      containers:
      - name: app-container
        image: sireregistry.azurecr.io/production-app:latest
        volumeMounts:
        - name: app-data
          mountPath: /app/data
        - name: app-config
          mountPath: /app/config
        env:
        - name: ENVIRONMENT
          value: "SIRE-Recovery"
        - name: DATABASE_CONNECTION
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: connection-string
      volumes:
      - name: app-data
        persistentVolumeClaim:
          claimName: app-data-pvc
      - name: app-config
        configMap:
          name: app-config
```

#### Container Registry Backup
```bash
#!/bin/bash
# Container image backup script for SIRE

PROD_REGISTRY="prodregistry.azurecr.io"
SIRE_REGISTRY="sireregistry.azurecr.io"
BACKUP_STORAGE="stsirebackup"

# Function to backup container images
backup_container_images() {
    local namespace=$1
    local app_name=$2
    
    echo "Backing up container images for $app_name in namespace $namespace"
    
    # Get current image tags
    kubectl get deployments -n "$namespace" -o jsonpath='{range .items[*]}{.spec.template.spec.containers[*].image}{"\n"}{end}' > /tmp/current-images.txt
    
    while IFS= read -r image; do
        if [[ $image == $PROD_REGISTRY* ]]; then
            # Extract image name and tag
            image_name=$(echo "$image" | cut -d'/' -f2 | cut -d':' -f1)
            image_tag=$(echo "$image" | cut -d':' -f2)
            
            echo "Backing up image: $image_name:$image_tag"
            
            # Pull from production registry
            docker pull "$image"
            
            # Tag for SIRE registry
            docker tag "$image" "$SIRE_REGISTRY/$image_name:$image_tag"
            docker tag "$image" "$SIRE_REGISTRY/$image_name:backup-$(date +%Y%m%d)"
            
            # Push to SIRE registry
            docker push "$SIRE_REGISTRY/$image_name:$image_tag"
            docker push "$SIRE_REGISTRY/$image_name:backup-$(date +%Y%m%d)"
            
            # Create manifest backup
            docker manifest inspect "$image" > "/tmp/$image_name-$image_tag-manifest.json"
            
            # Upload manifest to backup storage
            az storage blob upload \
                --account-name "$BACKUP_STORAGE" \
                --container-name "container-manifests" \
                --file "/tmp/$image_name-$image_tag-manifest.json" \
                --name "$image_name/$image_tag/manifest.json"
        fi
    done < /tmp/current-images.txt
    
    echo "Container image backup completed"
}

# Function to backup configuration
backup_kubernetes_config() {
    local namespace=$1
    local backup_path="/backup/k8s-config/$(date +%Y%m%d)"
    
    mkdir -p "$backup_path"
    
    # Backup deployments
    kubectl get deployments -n "$namespace" -o yaml > "$backup_path/deployments.yaml"
    
    # Backup services
    kubectl get services -n "$namespace" -o yaml > "$backup_path/services.yaml"
    
    # Backup configmaps
    kubectl get configmaps -n "$namespace" -o yaml > "$backup_path/configmaps.yaml"
    
    # Backup secrets (encrypted)
    kubectl get secrets -n "$namespace" -o yaml | \
        gpg --symmetric --cipher-algo AES256 --compress-algo 1 --output "$backup_path/secrets.yaml.gpg"
    
    # Backup persistent volume claims
    kubectl get pvc -n "$namespace" -o yaml > "$backup_path/pvc.yaml"
    
    # Backup ingress
    kubectl get ingress -n "$namespace" -o yaml > "$backup_path/ingress.yaml"
    
    # Upload to Azure Storage
    az storage blob upload-batch \
        --destination "kubernetes-backups" \
        --source "$backup_path" \
        --account-name "$BACKUP_STORAGE" \
        --destination-path "$(date +%Y%m%d)/$namespace"
    
    echo "Kubernetes configuration backup completed for namespace: $namespace"
}

# Main backup execution
NAMESPACES=("production" "staging" "shared-services")

for namespace in "${NAMESPACES[@]}"; do
    backup_container_images "$namespace" "all"
    backup_kubernetes_config "$namespace"
done
```

### Database Backup for Container Apps
```yaml
# Database backup job for containerized applications
apiVersion: batch/v1
kind: CronJob
metadata:
  name: database-backup-job
  namespace: sire-recovery
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: db-backup
            image: sireregistry.azurecr.io/db-backup-tool:latest
            command:
            - /bin/bash
            - -c
            - |
              echo "Starting database backup..."
              
              # PostgreSQL backup
              PGPASSWORD=$POSTGRES_PASSWORD pg_dump \
                -h $POSTGRES_HOST \
                -U $POSTGRES_USER \
                -d $POSTGRES_DB \
                --format=custom \
                --compress=9 \
                --verbose \
                --file=/backup/postgres-$(date +%Y%m%d-%H%M%S).backup
              
              # Upload to Azure Storage
              az storage blob upload \
                --account-name $STORAGE_ACCOUNT \
                --container-name database-backups \
                --file /backup/postgres-*.backup \
                --name "postgres/$(date +%Y%m%d)/postgres-$(date +%Y%m%d-%H%M%S).backup"
              
              echo "Database backup completed"
            env:
            - name: POSTGRES_HOST
              valueFrom:
                configMapKeyRef:
                  name: database-config
                  key: host
            - name: POSTGRES_USER
              valueFrom:
                secretKeyRef:
                  name: database-secret
                  key: username
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: database-secret
                  key: password
            - name: POSTGRES_DB
              valueFrom:
                configMapKeyRef:
                  name: database-config
                  key: database
            - name: STORAGE_ACCOUNT
              value: "stsirebackup"
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            emptyDir: {}
          restartPolicy: OnFailure
```

## Recovery Procedures

### Container App Recovery Workflow

#### 1. Environment Preparation
```bash
#!/bin/bash
# SIRE Container Apps environment preparation

SIRE_NAMESPACE="sire-recovery"
SIRE_REGISTRY="sireregistry.azurecr.io"
RECOVERY_DATE=$(date +%Y%m%d)

# Create SIRE namespace
kubectl create namespace "$SIRE_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Label namespace for network policies
kubectl label namespace "$SIRE_NAMESPACE" name=sire-recovery --overwrite

# Create image pull secret
kubectl create secret docker-registry sire-registry-secret \
    --namespace="$SIRE_NAMESPACE" \
    --docker-server="$SIRE_REGISTRY" \
    --docker-username="$SIRE_REGISTRY_USER" \
    --docker-password="$SIRE_REGISTRY_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f -

# Create service account
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sire-recovery-sa
  namespace: $SIRE_NAMESPACE
imagePullSecrets:
- name: sire-registry-secret
EOF

echo "SIRE environment prepared"
```

#### 2. Configuration Recovery
```bash
#!/bin/bash
# Recover application configuration

recover_configuration() {
    local source_namespace=$1
    local target_namespace=$2
    local recovery_date=$3
    
    echo "Recovering configuration from $source_namespace to $target_namespace"
    
    # Download configuration backup
    az storage blob download-batch \
        --destination "/tmp/config-recovery" \
        --source "kubernetes-backups" \
        --account-name "stsirebackup" \
        --pattern "$recovery_date/$source_namespace/*"
    
    # Apply configurations with namespace transformation
    for config_file in /tmp/config-recovery/$recovery_date/$source_namespace/*.yaml; do
        if [[ -f "$config_file" ]]; then
            echo "Processing $config_file"
            
            # Transform namespace and apply
            sed "s/namespace: $source_namespace/namespace: $target_namespace/g" "$config_file" | \
            sed "s/$source_namespace/$target_namespace/g" | \
            kubectl apply -f -
        fi
    done
    
    # Decrypt and apply secrets
    if [[ -f "/tmp/config-recovery/$recovery_date/$source_namespace/secrets.yaml.gpg" ]]; then
        gpg --decrypt "/tmp/config-recovery/$recovery_date/$source_namespace/secrets.yaml.gpg" | \
        sed "s/namespace: $source_namespace/namespace: $target_namespace/g" | \
        kubectl apply -f -
    fi
    
    echo "Configuration recovery completed"
}

# Example usage
recover_configuration "production" "sire-recovery" "$(date +%Y%m%d)"
```

#### 3. Application Recovery
```yaml
# SIRE recovery deployment template
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sire-production-app
  namespace: sire-recovery
  labels:
    app: production-app
    environment: sire-recovery
spec:
  replicas: 2
  selector:
    matchLabels:
      app: production-app
      environment: sire-recovery
  template:
    metadata:
      labels:
        app: production-app
        environment: sire-recovery
    spec:
      serviceAccountName: sire-recovery-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: production-app
        image: sireregistry.azurecr.io/production-app:backup-20240115
        imagePullPolicy: Always
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: ENVIRONMENT
          value: "SIRE-Recovery"
        - name: DATABASE_HOST
          value: "sire-database.sire-recovery.svc.cluster.local"
        - name: REDIS_HOST
          value: "sire-redis.sire-recovery.svc.cluster.local"
        - name: LOG_LEVEL
          value: "INFO"
        envFrom:
        - configMapRef:
            name: app-config
        - secretRef:
            name: app-secrets
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: cache-volume
          mountPath: /app/cache
        - name: data-volume
          mountPath: /app/data
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: tmp-volume
        emptyDir: {}
      - name: cache-volume
        emptyDir: {}
      - name: data-volume
        persistentVolumeClaim:
          claimName: app-data-pvc
      nodeSelector:
        kubernetes.io/arch: amd64
      tolerations:
      - key: "sire-recovery"
        operator: "Equal"
        value: "true"
        effect: "NoSchedule"

---
apiVersion: v1
kind: Service
metadata:
  name: sire-production-app-service
  namespace: sire-recovery
  labels:
    app: production-app
    environment: sire-recovery
spec:
  selector:
    app: production-app
    environment: sire-recovery
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  type: ClusterIP

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sire-production-app-ingress
  namespace: sire-recovery
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "sire-ca-issuer"
spec:
  tls:
  - hosts:
    - sire-app.internal.contoso.com
    secretName: sire-app-tls
  rules:
  - host: sire-app.internal.contoso.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: sire-production-app-service
            port:
              number: 80
```

### Database Recovery for Container Apps

#### PostgreSQL Recovery
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: sire-postgresql
  namespace: sire-recovery
spec:
  serviceName: "sire-postgresql"
  replicas: 1
  selector:
    matchLabels:
      app: sire-postgresql
  template:
    metadata:
      labels:
        app: sire-postgresql
    spec:
      containers:
      - name: postgresql
        image: postgres:14-alpine
        env:
        - name: POSTGRES_DB
          value: "productiondb"
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: postgresql-secret
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgresql-secret
              key: password
        - name: PGDATA
          value: "/var/lib/postgresql/data/pgdata"
        ports:
        - containerPort: 5432
          name: postgresql
        volumeMounts:
        - name: postgresql-data
          mountPath: /var/lib/postgresql/data
        - name: backup-restore
          mountPath: /backup
        lifecycle:
          postStart:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                # Wait for PostgreSQL to be ready
                until pg_isready -U $POSTGRES_USER -d $POSTGRES_DB; do
                  echo "Waiting for PostgreSQL to be ready..."
                  sleep 5
                done
                
                # Restore from backup if available
                if [ -f /backup/latest.backup ]; then
                  echo "Restoring database from backup..."
                  pg_restore -U $POSTGRES_USER -d $POSTGRES_DB -v /backup/latest.backup
                  echo "Database restore completed"
                fi
      initContainers:
      - name: backup-downloader
        image: mcr.microsoft.com/azure-cli:latest
        command:
        - /bin/bash
        - -c
        - |
          echo "Downloading latest database backup..."
          az storage blob download \
            --account-name stsirebackup \
            --container-name database-backups \
            --name "postgres/$(date +%Y%m%d)/latest.backup" \
            --file /backup/latest.backup \
            --auth-mode login
        volumeMounts:
        - name: backup-restore
          mountPath: /backup
        env:
        - name: AZURE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: client-id
        - name: AZURE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: client-secret
        - name: AZURE_TENANT_ID
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: tenant-id
  volumeClaimTemplates:
  - metadata:
      name: postgresql-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
  - metadata:
      name: backup-restore
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

### Automated Recovery Scripts

#### Complete Application Stack Recovery
```bash
#!/bin/bash
# Complete SIRE container apps recovery script

set -e

# Configuration
SIRE_NAMESPACE="sire-recovery"
PROD_NAMESPACE="production"
RECOVERY_DATE=${1:-$(date +%Y%m%d)}
APPS_TO_RECOVER=("web-app" "api-service" "worker-service")
DATABASE_REQUIRED=true

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check kubectl access
    if ! kubectl cluster-info &> /dev/null; then
        log "ERROR: kubectl not configured or cluster not accessible"
        exit 1
    fi
    
    # Check Azure CLI access
    if ! az account show &> /dev/null; then
        log "ERROR: Azure CLI not authenticated"
        exit 1
    fi
    
    # Check container registry access
    if ! az acr login --name sireregistry &> /dev/null; then
        log "ERROR: Cannot authenticate to SIRE container registry"
        exit 1
    fi
    
    log "Prerequisites check completed"
}

# Function to prepare SIRE environment
prepare_sire_environment() {
    log "Preparing SIRE environment..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace "$SIRE_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply network policies
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sire-isolation-policy
  namespace: $SIRE_NAMESPACE
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: sire-management
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: sire-storage
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
EOF
    
    # Create service account and RBAC
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sire-recovery-sa
  namespace: $SIRE_NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: $SIRE_NAMESPACE
  name: sire-recovery-role
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "create", "update", "patch"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sire-recovery-binding
  namespace: $SIRE_NAMESPACE
subjects:
- kind: ServiceAccount
  name: sire-recovery-sa
  namespace: $SIRE_NAMESPACE
roleRef:
  kind: Role
  name: sire-recovery-role
  apiGroup: rbac.authorization.k8s.io
EOF
    
    log "SIRE environment prepared"
}

# Function to recover database
recover_database() {
    if [ "$DATABASE_REQUIRED" = true ]; then
        log "Starting database recovery..."
        
        # Apply PostgreSQL StatefulSet
        kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: sire-postgresql
  namespace: $SIRE_NAMESPACE
spec:
  serviceName: "sire-postgresql"
  replicas: 1
  selector:
    matchLabels:
      app: sire-postgresql
  template:
    metadata:
      labels:
        app: sire-postgresql
    spec:
      containers:
      - name: postgresql
        image: postgres:14-alpine
        env:
        - name: POSTGRES_DB
          value: "productiondb"
        - name: POSTGRES_USER
          value: "postgres"
        - name: POSTGRES_PASSWORD
          value: "sire-recovery-password"
        ports:
        - containerPort: 5432
          name: postgresql
        volumeMounts:
        - name: postgresql-data
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgresql-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
EOF
        
        # Wait for database to be ready
        log "Waiting for database to be ready..."
        kubectl wait --for=condition=ready pod -l app=sire-postgresql -n "$SIRE_NAMESPACE" --timeout=300s
        
        log "Database recovery completed"
    fi
}

# Function to recover application
recover_application() {
    local app_name=$1
    log "Recovering application: $app_name"
    
    # Download application manifests
    az storage blob download \
        --account-name stsirebackup \
        --container-name kubernetes-backups \
        --name "$RECOVERY_DATE/$PROD_NAMESPACE/deployments.yaml" \
        --file "/tmp/$app_name-deployment.yaml"
    
    # Transform and apply deployment
    sed -e "s/namespace: $PROD_NAMESPACE/namespace: $SIRE_NAMESPACE/g" \
        -e "s/prodregistry.azurecr.io/sireregistry.azurecr.io/g" \
        -e "s/:latest/:backup-$RECOVERY_DATE/g" \
        "/tmp/$app_name-deployment.yaml" | \
    kubectl apply -f -
    
    log "Application $app_name recovery completed"
}

# Function to verify recovery
verify_recovery() {
    log "Verifying recovery..."
    
    # Check pod status
    kubectl get pods -n "$SIRE_NAMESPACE" -o wide
    
    # Check services
    kubectl get services -n "$SIRE_NAMESPACE"
    
    # Health check for each application
    for app in "${APPS_TO_RECOVER[@]}"; do
        log "Health checking $app..."
        
        # Wait for pods to be ready
        kubectl wait --for=condition=ready pod -l app="$app" -n "$SIRE_NAMESPACE" --timeout=300s
        
        # Get service endpoint
        SERVICE_IP=$(kubectl get service "${app}-service" -n "$SIRE_NAMESPACE" -o jsonpath='{.spec.clusterIP}')
        
        # Perform health check
        if kubectl run health-check-"$app" --rm -i --tty --image=curlimages/curl -- curl -f "http://$SERVICE_IP/health" &> /dev/null; then
            log "✓ $app is healthy"
        else
            log "✗ $app health check failed"
        fi
    done
    
    log "Recovery verification completed"
}

# Function to generate recovery report
generate_recovery_report() {
    log "Generating recovery report..."
    
    local report_file="/tmp/sire-recovery-report-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$report_file" <<EOF
{
  "recoveryDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "sourceNamespace": "$PROD_NAMESPACE",
  "targetNamespace": "$SIRE_NAMESPACE",
  "backupDate": "$RECOVERY_DATE",
  "recoveredApplications": $(printf '%s\n' "${APPS_TO_RECOVER[@]}" | jq -R . | jq -s .),
  "databaseRecovered": $DATABASE_REQUIRED,
  "podStatus": $(kubectl get pods -n "$SIRE_NAMESPACE" -o json | jq '.items[] | {name: .metadata.name, status: .status.phase, ready: .status.conditions[]? | select(.type=="Ready") | .status}'),
  "serviceStatus": $(kubectl get services -n "$SIRE_NAMESPACE" -o json | jq '.items[] | {name: .metadata.name, type: .spec.type, clusterIP: .spec.clusterIP}')
}
EOF
    
    # Upload report to storage
    az storage blob upload \
        --account-name stsirebackup \
        --container-name recovery-reports \
        --file "$report_file" \
        --name "sire-recovery-report-$(date +%Y%m%d-%H%M%S).json"
    
    log "Recovery report generated: $report_file"
}

# Main execution
main() {
    log "Starting SIRE container apps recovery..."
    log "Recovery date: $RECOVERY_DATE"
    log "Target namespace: $SIRE_NAMESPACE"
    log "Applications to recover: ${APPS_TO_RECOVER[*]}"
    
    check_prerequisites
    prepare_sire_environment
    
    if [ "$DATABASE_REQUIRED" = true ]; then
        recover_database
    fi
    
    for app in "${APPS_TO_RECOVER[@]}"; do
        recover_application "$app"
    done
    
    verify_recovery
    generate_recovery_report
    
    log "SIRE container apps recovery completed successfully!"
}

# Execute main function
main "$@"
```

## Security Considerations

### Container Security in SIRE

#### Image Security Scanning
```yaml
# Security scanning pipeline for SIRE container images
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: sire-security-scan-pipeline
  namespace: sire-recovery
spec:
  params:
  - name: image-url
    type: string
    description: Container image URL to scan
  - name: severity-threshold
    type: string
    default: "HIGH"
    description: Minimum severity to fail the scan
  tasks:
  - name: vulnerability-scan
    taskRef:
      name: trivy-scanner
    params:
    - name: IMAGE
      value: $(params.image-url)
    - name: SEVERITY
      value: $(params.severity-threshold)
  - name: policy-check
    taskRef:
      name: opa-policy-check
    runAfter:
    - vulnerability-scan
    params:
    - name: IMAGE
      value: $(params.image-url)
  - name: sign-image
    taskRef:
      name: cosign-signer
    runAfter:
    - policy-check
    params:
    - name: IMAGE
      value: $(params.image-url)
    - name: KEY_REF
      value: "sire-signing-key"
```

#### Runtime Security Policies
```yaml
# Pod Security Policy for SIRE namespace
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: sire-restricted-psp
  namespace: sire-recovery
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
  - ALL
  volumes:
  - 'configMap'
  - 'emptyDir'
  - 'projected'
  - 'secret'
  - 'downwardAPI'
  - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
  
---
# Network Policy for SIRE isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sire-network-isolation
  namespace: sire-recovery
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: sire-management
    - namespaceSelector:
        matchLabels:
          name: sire-monitoring
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: sire-storage
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to: []
    ports:
    - protocol: TCP
      port: 443
```

### Secrets Management

#### Azure Key Vault Integration
```yaml
# Secret Provider Class for Azure Key Vault
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: sire-keyvault-secrets
  namespace: sire-recovery
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    userAssignedIdentityID: "sire-managed-identity-client-id"
    keyvaultName: "kv-sire-primary-prod"
    tenantId: "tenant-id"
    objects: |
      array:
        - |
          objectName: database-password
          objectType: secret
          objectVersion: ""
        - |
          objectName: api-key
          objectType: secret
          objectVersion: ""
        - |
          objectName: certificate
          objectType: cert
          objectVersion: ""
  secretObjects:
  - secretName: database-secret
    type: Opaque
    data:
    - objectName: database-password
      key: password
  - secretName: api-secret
    type: Opaque
    data:
    - objectName: api-key
      key: api-key

---
# Example pod using secrets from Key Vault
apiVersion: v1
kind: Pod
metadata:
  name: sire-app-with-secrets
  namespace: sire-recovery
spec:
  serviceAccountName: sire-recovery-sa
  containers:
  - name: app
    image: sireregistry.azurecr.io/secure-app:latest
    env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: database-secret
          key: password
    volumeMounts:
    - name: secrets-store
      mountPath: /mnt/secrets-store
      readOnly: true
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: sire-keyvault-secrets
```

## Monitoring and Observability

### Application Performance Monitoring
```yaml
# Prometheus monitoring for SIRE applications
apiVersion: v1
kind: ServiceMonitor
metadata:
  name: sire-app-monitoring
  namespace: sire-recovery
spec:
  selector:
    matchLabels:
      monitoring: enabled
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
    
---
# Grafana dashboard ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: sire-dashboard
  namespace: sire-recovery
data:
  sire-dashboard.json: |
    {
      "dashboard": {
        "title": "SIRE Applications Dashboard",
        "panels": [
          {
            "title": "Pod Status",
            "type": "stat",
            "targets": [
              {
                "expr": "kube_pod_status_phase{namespace=\"sire-recovery\"}",
                "legendFormat": "{{pod}} - {{phase}}"
              }
            ]
          },
          {
            "title": "CPU Usage",
            "type": "graph",
            "targets": [
              {
                "expr": "rate(container_cpu_usage_seconds_total{namespace=\"sire-recovery\"}[5m])",
                "legendFormat": "{{pod}}"
              }
            ]
          },
          {
            "title": "Memory Usage",
            "type": "graph",
            "targets": [
              {
                "expr": "container_memory_usage_bytes{namespace=\"sire-recovery\"}",
                "legendFormat": "{{pod}}"
              }
            ]
          }
        ]
      }
    }
```

### Logging Configuration
```yaml
# Fluentd DaemonSet for SIRE log collection
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd-sire
  namespace: sire-recovery
spec:
  selector:
    matchLabels:
      name: fluentd-sire
  template:
    metadata:
      labels:
        name: fluentd-sire
    spec:
      serviceAccountName: fluentd
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1.14-debian-elasticsearch7-1
        env:
        - name: FLUENT_ELASTICSEARCH_HOST
          value: "elasticsearch.sire-monitoring.svc.cluster.local"
        - name: FLUENT_ELASTICSEARCH_PORT
          value: "9200"
        - name: FLUENT_ELASTICSEARCH_SCHEME
          value: "http"
        - name: FLUENT_UID
          value: "0"
        - name: FLUENT_ELASTICSEARCH_INDEX_NAME
          value: "sire-logs"
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: fluentd-config
          mountPath: /fluentd/etc/fluent.conf
          subPath: fluent.conf
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
      - name: fluentd-config
        configMap:
          name: fluentd-config
```

## Performance Optimization

### Resource Management
```yaml
# Horizontal Pod Autoscaler for SIRE applications
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sire-app-hpa
  namespace: sire-recovery
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sire-production-app
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 60

---
# Vertical Pod Autoscaler
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: sire-app-vpa
  namespace: sire-recovery
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sire-production-app
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: production-app
      minAllowed:
        cpu: 100m
        memory: 128Mi
      maxAllowed:
        cpu: 2
        memory: 2Gi
```

## Testing and Validation

### Automated Testing Pipeline
```yaml
# Container Apps testing pipeline
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: sire-testing-pipeline
  namespace: sire-recovery
spec:
  params:
  - name: app-name
    type: string
  - name: namespace
    type: string
    default: sire-recovery
  tasks:
  - name: health-check
    taskSpec:
      params:
      - name: app-name
        type: string
      - name: namespace
        type: string
      steps:
      - name: check-pods
        image: bitnami/kubectl:latest
        script: |
          #!/bin/bash
          kubectl wait --for=condition=ready pod -l app=$(params.app-name) -n $(params.namespace) --timeout=300s
          kubectl get pods -l app=$(params.app-name) -n $(params.namespace)
      - name: check-service
        image: curlimages/curl:latest
        script: |
          #!/bin/bash
          SERVICE_IP=$(kubectl get service $(params.app-name)-service -n $(params.namespace) -o jsonpath='{.spec.clusterIP}')
          curl -f http://$SERVICE_IP/health || exit 1
  - name: load-test
    runAfter:
    - health-check
    taskSpec:
      params:
      - name: app-name
        type: string
      - name: namespace
        type: string
      steps:
      - name: run-load-test
        image: fortio/fortio:latest
        script: |
          #!/bin/bash
          SERVICE_IP=$(kubectl get service $(params.app-name)-service -n $(params.namespace) -o jsonpath='{.spec.clusterIP}')
          fortio load -c 10 -t 60s http://$SERVICE_IP/
  - name: security-scan
    runAfter:
    - health-check
    taskSpec:
      params:
      - name: app-name
        type: string
      - name: namespace
        type: string
      steps:
      - name: run-security-scan
        image: aquasec/trivy:latest
        script: |
          #!/bin/bash
          IMAGE=$(kubectl get deployment $(params.app-name) -n $(params.namespace) -o jsonpath='{.spec.template.spec.containers[0].image}')
          trivy image --severity HIGH,CRITICAL $IMAGE
```

## Cost Optimization

### Resource Efficiency
```yaml
# Resource Quota for SIRE namespace
apiVersion: v1
kind: ResourceQuota
metadata:
  name: sire-resource-quota
  namespace: sire-recovery
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    persistentvolumeclaims: "10"
    pods: "50"
    services: "20"

---
# Limit Range for pods
apiVersion: v1
kind: LimitRange
metadata:
  name: sire-limit-range
  namespace: sire-recovery
spec:
  limits:
  - default:
      cpu: 500m
      memory: 512Mi
    defaultRequest:
      cpu: 100m
      memory: 128Mi
    type: Container
  - max:
      cpu: 2
      memory: 2Gi
    min:
      cpu: 50m
      memory: 64Mi
    type: Container
```

### Cluster Autoscaling
```yaml
# Cluster Autoscaler configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-autoscaler-sire
  namespace: kube-system
data:
  cluster-autoscaler.yaml: |
    nodes:
      - name: sire-nodepool
        minSize: 2
        maxSize: 10
        desiredCapacity: 3
    scaleDownDelayAfterAdd: 10m
    scaleDownUnneededTime: 10m
    scaleDownUtilizationThreshold: 0.5
    skipNodesWithLocalStorage: false
    skipNodesWithSystemPods: false
```

## Next Steps

1. Review [Virtual Machines Guide](./virtual-machines-guide.md) for VM-based workloads
2. Implement database-specific procedures from [Database Workload Guide](./database-guide.md)
3. Configure monitoring using [Operations Guide](../operations-guide.md)
4. Schedule testing procedures from [Testing Guide](../testing-guide.md)
5. Review [Security Guidelines](../security-guidelines.md) for additional security measures