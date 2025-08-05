# zerossl-issuer

A cert-manager external issuer for ZeroSSL that enables automated SSL/TLS certificate management using the ZeroSSL API.

## Overview

This project implements a [cert-manager](https://cert-manager.io) external issuer that integrates with [ZeroSSL](https://zerossl.com) to automate the process of obtaining, renewing, and managing SSL/TLS certificates in Kubernetes clusters.

## Prerequisites

- Kubernetes cluster (v1.19+)
- cert-manager (v1.6.0+)
- ZeroSSL API key

## Installation

### Using Helm (Recommended)

1. Install cert-manager (if not already installed):
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
   ```

2. Install the ZeroSSL issuer using Helm:
   ```bash
   # Clone the repository (if you don't have the chart locally)
   git clone https://github.com/topfreegames/zerossl-issuer.git
   cd zerossl-issuer
   
   # Install the chart
   helm install zerossl-issuer ./helm/zerossl-issuer
   ```

   See the [Helm chart README](./helm/zerossl-issuer/README.md) for detailed configuration options.

### Manual Installation

1. Install cert-manager (if not already installed):
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
   ```

2. Install the ZeroSSL issuer:
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/topfreegames/zerossl-issuer/main/config/crd/bases/zerossl.cert-manager.io_issuers.yaml
   kubectl apply -f https://raw.githubusercontent.com/topfreegames/zerossl-issuer/main/config/crd/bases/zerossl.cert-manager.io_challenges.yaml
   kubectl apply -f https://raw.githubusercontent.com/topfreegames/zerossl-issuer/main/config/manager/manager.yaml
   ```

## Configuration

1. Create a Secret containing your ZeroSSL API key:
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: zerossl-api-key
     namespace: cert-manager
   type: Opaque
   stringData:
     api-key: your-api-key-here
   ```

2. Create a ZeroSSL Issuer:

   ### Basic Issuer
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
     validityDays: 90  # Optional: defaults to 90
     strictDomains: true  # Optional: defaults to true
   ```

   ### Issuer with DNS Validation (Route53)
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

3. Create AWS credentials secret for Route53 (if using DNS validation):
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: route53-credentials
     namespace: default
   type: Opaque
   stringData:
     secret: your-aws-secret-key-here
   ```

## Usage

Once the issuer is configured, you can create certificates using cert-manager's Certificate resource:

### Standard Certificate
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: zerossl-issuer
    kind: Issuer
    group: zerossl.cert-manager.io
  dnsNames:
    - example.com
    - www.example.com
```

### Wildcard Certificate with DNS Validation
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: wildcard-example-com
  namespace: default
spec:
  secretName: wildcard-example-com-tls
  issuerRef:
    name: zerossl-dns-issuer
    kind: Issuer
    group: zerossl.cert-manager.io
  dnsNames:
    - "*.example.com"  # ZeroSSL wildcard certificates must be single domain only
```

### Using with NGINX Ingress Controller

The ZeroSSL issuer integrates seamlessly with NGINX Ingress Controller using cert-manager annotations. Here's a basic example:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: default
  annotations:
    # Enable cert-manager to automatically create certificates
    cert-manager.io/issuer: "zerossl-issuer"
    cert-manager.io/issuer-kind: "Issuer"
    cert-manager.io/issuer-group: "zerossl.cert-manager.io"
    
    # NGINX Ingress Controller annotations
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

#### Key annotations for ZeroSSL issuer:
- `cert-manager.io/issuer`: Name of your ZeroSSL issuer
- `cert-manager.io/issuer-kind`: Set to "Issuer" or "ClusterIssuer"
- `cert-manager.io/issuer-group`: Set to "zerossl.cert-manager.io"

#### Additional cert-manager annotations you can use:
- `cert-manager.io/duration`: Certificate validity period (e.g., "2160h" for 90 days)
- `cert-manager.io/renew-before`: When to start renewal process (e.g., "720h" for 30 days before expiry)

**Important:** ZeroSSL wildcard certificates must be single domain only (e.g., `*.example.com`). You cannot combine wildcards with other domains in the same certificate.

For more comprehensive examples including wildcard certificates and advanced configurations, see [config/samples/nginx_ingress_example.yaml](config/samples/nginx_ingress_example.yaml).

## Development

### Prerequisites

- Go 1.21+
- Kubebuilder
- Docker

### Building

1. Clone the repository:
   ```bash
   git clone https://github.com/topfreegames/zerossl-issuer.git
   cd zerossl-issuer
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Build the controller:
   ```bash
   make
   ```

### Testing

Run the test suite:
```bash
make test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
