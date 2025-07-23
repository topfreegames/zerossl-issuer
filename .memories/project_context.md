# ZeroSSL Issuer Project Memory Bank

This file contains important context and information about the ZeroSSL Issuer project that should be preserved across development sessions.

## Project Overview

The ZeroSSL Issuer is a cert-manager external issuer that integrates with ZeroSSL's API to automate SSL/TLS certificate management in Kubernetes clusters. It follows the cert-manager external issuer pattern and uses kubebuilder for implementation.

## Project Structure

- **Domain**: zerossl.cert-manager.io
- **Repository**: github.com/ronnansouza/zerossl-issuer
- **Framework**: Kubebuilder with Go modules for dependency management

## Core Components

### API Types (v1alpha1)

The ZeroSSL issuer API is defined in v1alpha1 with the following fields:

- **Required Fields**:
  - `apiKey`: Authentication key for ZeroSSL API

- **Optional Fields**:
  - `validityDays`: Certificate validity period (1-365 days, default: 90)
  - `strictDomains`: Domain validation strictness (default: true)

### ZeroSSL Client

Located in the `internal/zerossl` package with two main components:

1. **client.go**:
   - Core client functionality
   - API key validation
   - Base HTTP client implementation
   - Error handling

2. **certificates.go**:
   - Certificate creation
   - Certificate retrieval
   - Certificate status management

### Controller Structure

The controller implements:
- Basic reconciliation loop
- Status condition management
- Logging
- Error handling
- API key validation

## Development Guidelines

1. **Code Organization**:
   - Use kubebuilder conventions
   - Follow Go best practices
   - Maintain clear package boundaries

2. **API Versioning**:
   - Current version: v1alpha1
   - Follow kubernetes API versioning guidelines

3. **Error Handling**:
   - Use detailed error messages
   - Implement proper status conditions
   - Log relevant information

4. **Testing**:
   - Write unit tests for all components
   - Include integration tests
   - Test error scenarios

## Future Enhancements

1. Certificate signing and validation logic
2. ClusterIssuer support
3. Certificate renewal implementation
4. Comprehensive test coverage
5. CI/CD pipeline setup

## Dependencies

- Go 1.21+
- Kubebuilder
- cert-manager
- Kubernetes v1.19+

## Notes

- The project follows cert-manager's external issuer framework
- Integration with ZeroSSL's REST API is required
- Key dependencies include kubebuilder and controller-runtime 