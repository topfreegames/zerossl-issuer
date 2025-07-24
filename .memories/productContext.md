# ZeroSSL Issuer Product Context

## Problem Statement
Managing SSL/TLS certificates in Kubernetes environments can be complex and time-consuming. While cert-manager provides a framework for certificate automation, organizations using ZeroSSL need a dedicated issuer to integrate with their service. Manual certificate management is error-prone and doesn't scale well in dynamic Kubernetes environments.

## Solution
ZeroSSL Issuer bridges the gap between cert-manager and ZeroSSL by providing:
1. Automated certificate lifecycle management
2. Native Kubernetes integration
3. Secure API key handling
4. Simplified certificate operations

## User Experience Goals

### For Kubernetes Administrators
1. Simple installation and configuration
2. Minimal manual intervention required
3. Clear visibility into certificate status
4. Easy troubleshooting through logs and metrics
5. Seamless integration with existing cert-manager workflows

### For Application Teams
1. Automatic certificate provisioning for their services
2. Zero-touch certificate renewal
3. Consistent certificate management across namespaces
4. Standard Kubernetes resource usage

## Key Workflows

### Certificate Issuance
1. User creates a Certificate resource referencing ZeroSSL issuer
2. Controller validates the request
3. ZeroSSL API is called to issue certificate
4. Certificate is stored in a Kubernetes Secret
5. Status is updated in the Certificate resource

### Certificate Renewal
1. Controller monitors certificate expiration
2. Automatic renewal process is triggered before expiry
3. New certificate is obtained from ZeroSSL
4. Secret is updated with new certificate
5. Status is updated to reflect renewal

### Error Handling
1. Clear error messages in resource status
2. Automatic retries for transient failures
3. Proper logging for troubleshooting
4. Metrics for monitoring failure rates

## Integration Points

### cert-manager Integration
- Implements cert-manager's issuer interface
- Uses cert-manager's CRD framework
- Follows cert-manager's security model

### ZeroSSL API Integration
- Secure API key management
- Efficient API usage
- Proper error handling
- Rate limiting compliance

### Kubernetes Integration
- Native resource management
- Standard RBAC model
- Prometheus metrics
- Health monitoring 