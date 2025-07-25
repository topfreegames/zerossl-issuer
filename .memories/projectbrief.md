# ZeroSSL Issuer Project Brief

## Project Overview
ZeroSSL Issuer is a cert-manager external issuer that integrates with ZeroSSL to automate SSL/TLS certificate management in Kubernetes clusters. It enables automated certificate issuance, renewal, and management using the ZeroSSL API.

## Core Requirements

### Functional Requirements
1. Implement a cert-manager external issuer for ZeroSSL
2. Automate SSL/TLS certificate lifecycle management
3. Support certificate issuance and renewal
4. Integrate with ZeroSSL API for certificate operations
5. Support Kubernetes-native certificate management
6. Support DNS validation for certificates, starting with Route53

### Technical Requirements
1. Kubernetes compatibility (v1.19+)
2. cert-manager compatibility (v1.6.0+)
3. Secure API key management
4. Support for multiple architectures (amd64, arm64, ppc64le, s390x)
5. Metrics and monitoring capabilities
6. Health checks and readiness probes
7. DNS validation via supported providers

### Security Requirements
1. Secure handling of ZeroSSL API keys
2. Pod Security Standards compliance (restricted)
3. Non-root container execution
4. Read-only root filesystem
5. Dropped Linux capabilities
6. Secure metrics endpoint (HTTPS)
7. Secure handling of DNS provider credentials

## Project Goals
1. Provide seamless integration between cert-manager and ZeroSSL
2. Simplify SSL/TLS certificate management in Kubernetes
3. Ensure high reliability and availability
4. Maintain security best practices
5. Support enterprise-grade deployments
6. Enable wildcard certificate management through DNS validation

## Success Criteria
1. Successful certificate issuance and renewal
2. Proper error handling and reporting
3. Comprehensive test coverage
4. Production-ready security measures
5. Clear documentation and usage examples
6. Stable performance under load
7. Successful DNS validation for certificates 