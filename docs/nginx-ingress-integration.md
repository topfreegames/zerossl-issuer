# NGINX Ingress Integration with ZeroSSL Issuer

This guide demonstrates how to use the ZeroSSL issuer with NGINX Ingress Controller to automatically provision SSL/TLS certificates for your applications.

## Prerequisites

- Kubernetes cluster with NGINX Ingress Controller installed
- cert-manager installed and running
- ZeroSSL issuer deployed and configured
- ZeroSSL API key
- (For wildcard certificates) DNS provider credentials (e.g., Route53)

## Quick Start

### 1. Create ZeroSSL API Key Secret

First, create a secret containing your ZeroSSL API key:

```bash
kubectl create secret generic zerossl-api-key \
  --from-literal=api-key=your-api-key-here \
  --namespace=default
```

### 2. Create ZeroSSL Issuer

For basic certificates (HTTP validation):

```yaml
apiVersion: zerossl.cert-manager.io/v1alpha1
kind: Issuer
metadata:
  name: zerossl-issuer
  namespace: default
spec:
  apiKeySecretRef:
    name: zerossl-api-key
    key: api-key
  validityDays: 90
  strictDomains: true
```

For wildcard certificates (DNS validation with Route53):

```yaml
apiVersion: zerossl.cert-manager.io/v1alpha1
kind: Issuer
metadata:
  name: zerossl-dns-issuer
  namespace: default
spec:
  apiKeySecretRef:
    name: zerossl-api-key
    key: api-key
  validityDays: 90
  strictDomains: true
  solvers:
  - dns01:
      route53:
        accessKeyID: AKIAEXAMPLE123456789
        hostedZoneID: Z2E9THH2A4HU6P
        region: us-east-1
        secretAccessKeySecretRef:
          key: secret
          name: route53-credentials
    selector:
      dnsZones:
      - example.com
```

### 3. Create NGINX Ingress with ZeroSSL Certificate

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  namespace: default
  annotations:
    # ZeroSSL issuer configuration
    cert-manager.io/issuer: "zerossl-issuer"
    cert-manager.io/issuer-kind: "Issuer"
    cert-manager.io/issuer-group: "zerossl.cert-manager.io"
    
    # NGINX Ingress Controller configuration
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls-certificate
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

## Configuration Options

### Required Annotations

For ZeroSSL issuer integration, you must include these annotations:

```yaml
annotations:
  cert-manager.io/issuer: "your-issuer-name"           # Name of your ZeroSSL issuer
  cert-manager.io/issuer-kind: "Issuer"                # Or "ClusterIssuer"
  cert-manager.io/issuer-group: "zerossl.cert-manager.io"  # ZeroSSL issuer group
```

### Optional cert-manager Annotations

```yaml
annotations:
  # Certificate duration (default: 90 days for ZeroSSL)
  cert-manager.io/duration: "2160h"  # 90 days
  
  # When to start renewal process (recommended: 30 days before expiry)
  cert-manager.io/renew-before: "720h"  # 30 days
  
  # Common name for the certificate (usually first DNS name)
  cert-manager.io/common-name: "app.example.com"
  
  # Subject alternative names (additional DNS names)
  cert-manager.io/alt-names: "api.example.com,admin.example.com"
```

### NGINX Ingress Controller Annotations

Common NGINX annotations you'll want to use:

```yaml
annotations:
  # Basic SSL configuration
  kubernetes.io/ingress.class: "nginx"
  nginx.ingress.kubernetes.io/ssl-redirect: "true"
  nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
  
  # SSL protocols and ciphers
  nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
  nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384"
  
  # Proxy settings
  nginx.ingress.kubernetes.io/proxy-body-size: "50m"
  nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
  nginx.ingress.kubernetes.io/proxy-send-timeout: "30"
  nginx.ingress.kubernetes.io/proxy-read-timeout: "30"
  
  # Security headers
  nginx.ingress.kubernetes.io/configuration-snippet: |
    more_set_headers "X-Frame-Options: DENY";
    more_set_headers "X-Content-Type-Options: nosniff";
    more_set_headers "X-XSS-Protection: 1; mode=block";
```

## Advanced Examples

### Wildcard Certificate

For wildcard certificates, you need DNS validation. **Important: ZeroSSL wildcard certificates must be single domain only.**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wildcard-ingress
  annotations:
    cert-manager.io/issuer: "zerossl-dns-issuer"  # Use DNS-enabled issuer
    cert-manager.io/issuer-kind: "Issuer"
    cert-manager.io/issuer-group: "zerossl.cert-manager.io"
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - "*.example.com"  # ZeroSSL wildcard certificates must be single domain only
    secretName: wildcard-certificate
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
```

### Multiple Ingresses Sharing a Certificate

You can share certificates across multiple ingresses:

```yaml
# First ingress - creates the certificate
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: main-app
  annotations:
    cert-manager.io/issuer: "zerossl-issuer"
    cert-manager.io/issuer-kind: "Issuer"
    cert-manager.io/issuer-group: "zerossl.cert-manager.io"
    kubernetes.io/ingress.class: "nginx"
spec:
  tls:
  - hosts:
    - app.example.com
    - api.example.com
    secretName: shared-certificate
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80

---
# Second ingress - reuses the certificate
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-app
  annotations:
    kubernetes.io/ingress.class: "nginx"
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: shared-certificate  # Same secret name
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
```

## Troubleshooting

### Check Certificate Status

```bash
# Check certificate resources
kubectl get certificates -n default

# Check certificate details
kubectl describe certificate app-tls-certificate -n default

# Check certificate request status
kubectl get certificaterequests -n default

# Check challenge status (for DNS validation)
kubectl get challenges -n default
```

### Check Ingress Status

```bash
# Check ingress resources
kubectl get ingress -n default

# Check ingress details
kubectl describe ingress my-app -n default

# Check TLS secret
kubectl get secret app-tls-certificate -n default -o yaml
```

### Common Issues

1. **Certificate not being created**: Verify the issuer name and annotations are correct
2. **DNS validation failing**: Check Route53 credentials and hosted zone configuration
3. **SSL not working**: Ensure the secret name matches between ingress and certificate
4. **Certificate not renewed**: Check renew-before annotation and issuer configuration

### Logs

```bash
# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Check ZeroSSL issuer logs
kubectl logs -n zerossl-system deployment/zerossl-issuer-controller-manager

# Check NGINX ingress controller logs
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller
```

## Best Practices

1. **Use ClusterIssuer for multiple namespaces**: If you have applications across multiple namespaces, consider using ClusterIssuer instead of Issuer
2. **Set appropriate renewal timing**: Use `cert-manager.io/renew-before` to start renewal well before expiry
3. **Monitor certificate expiration**: Set up monitoring for certificate expiration dates
4. **Use wildcard certificates sparingly**: Only use wildcards when you have many subdomains
5. **Wildcard certificate limitations**: ZeroSSL wildcard certificates must be single domain only (e.g., `*.example.com`). You cannot combine wildcards with other domains in the same certificate
6. **Secure your secrets**: Ensure API keys and DNS credentials are stored securely
7. **Test in staging first**: Always test certificate issuance in a staging environment

## Complete Working Example

For a complete working example with all components, see [config/samples/nginx_ingress_example.yaml](../config/samples/nginx_ingress_example.yaml).