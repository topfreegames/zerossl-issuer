# zerossl-issuer

A cert-manager external issuer for ZeroSSL that enables automated SSL/TLS certificate management using the ZeroSSL API.

## Overview

This project implements a [cert-manager](https://cert-manager.io) external issuer that integrates with [ZeroSSL](https://zerossl.com) to automate the process of obtaining, renewing, and managing SSL/TLS certificates in Kubernetes clusters.

## Prerequisites

- Kubernetes cluster (v1.19+)
- cert-manager (v1.6.0+)
- ZeroSSL API key

## Installation

1. Install cert-manager (if not already installed):
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
   ```

2. Install the ZeroSSL issuer:
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/ronnansouza/zerossl-issuer/main/config/crd/bases/zerossl.cert-manager.io_issuers.yaml
   kubectl apply -f https://raw.githubusercontent.com/ronnansouza/zerossl-issuer/main/config/manager/manager.yaml
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
   ```yaml
   apiVersion: zerossl.cert-manager.io/v1alpha1
   kind: Issuer
   metadata:
     name: zerossl-issuer
     namespace: default
   spec:
     apiKey: your-api-key-here
     validityDays: 90  # Optional: defaults to 90
     strictDomains: true  # Optional: defaults to true
   ```

## Usage

Once the issuer is configured, you can create certificates using cert-manager's Certificate resource:

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
