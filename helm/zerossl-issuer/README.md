# ZeroSSL cert-manager Issuer Helm Chart

This Helm chart installs the ZeroSSL cert-manager Issuer in your Kubernetes cluster. The ZeroSSL Issuer is a controller that integrates ZeroSSL with cert-manager, allowing you to obtain certificates through the ZeroSSL API.

## Prerequisites

- Kubernetes 1.16+
- Helm 3.0+
- cert-manager v1.0.0+

## Installation

### Installing cert-manager

The ZeroSSL Issuer requires cert-manager to be installed in your cluster. If you haven't installed it yet, follow the [official installation guide](https://cert-manager.io/docs/installation/).

### Installing the ZeroSSL Issuer

```bash
# Add the helm repository (if available)
# helm repo add zerossl-issuer https://topfreegames.github.io/zerossl-issuer
# helm repo update

# Install the chart with the release name zerossl-issuer
helm install zerossl-issuer ./helm/zerossl-issuer
```

By default, the chart will be installed in the cert-manager namespace, which is expected to already exist. If you want to install it in a different namespace or create a namespace as part of the installation, see the [Namespace Configuration](#namespace-configuration) section.

## Configuration

The following table lists the configurable parameters of the ZeroSSL Issuer chart and their default values.

| Parameter | Description | Default |
| --------- | ----------- | ------- |
| `namespace.name` | Namespace where the controller will be deployed | `cert-manager` |
| `namespace.create` | Whether to create the namespace | `false` |
| `image.repository` | Controller image repository | `topfreegames/zerossl-issuer` |
| `image.tag` | Controller image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of replicas | `1` |
| `commonLabels` | Labels to add to all resources | `{}` |
| `resources.limits.cpu` | CPU limits | `500m` |
| `resources.limits.memory` | Memory limits | `128Mi` |
| `resources.requests.cpu` | CPU requests | `10m` |
| `resources.requests.memory` | Memory requests | `64Mi` |
| `serviceAccount.create` | If true, create the service account | `true` |
| `serviceAccount.name` | Name of the service account | `""` |
| `podSecurityContext` | Pod security context | See values.yaml |
| `containerSecurityContext` | Container security context | See values.yaml |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | List of tolerations | `[]` |
| `affinity.nodeAffinity.enabled` | Enable node affinity | `false` |
| `leaderElection.enabled` | Enable leader election | `true` |
| `installCRDs` | Install CRDs | `true` |

### Namespace Configuration

By default, the chart assumes the cert-manager namespace already exists and will deploy resources there. You have two options for namespace configuration:

1. **Use an existing namespace (default):**
   - Set `namespace.name` to the name of the existing namespace (default: `cert-manager`)
   - Keep `namespace.create` as `false`

   ```yaml
   # values.yaml
   namespace:
     name: my-existing-namespace
     create: false
   ```

2. **Create a new namespace:**
   - Set `namespace.name` to your desired namespace name
   - Set `namespace.create` to `true`

   ```yaml
   # values.yaml
   namespace:
     name: zerossl-system
     create: true
   ```

### Adding Common Labels

You can add common labels to all resources created by this chart by setting the `commonLabels` parameter. This can be useful for filtering resources or integrating with organizational label standards.

Example:

```yaml
# values.yaml
commonLabels:
  environment: production
  app.kubernetes.io/part-of: cert-management
  department: platform-team
```

Use this when installing or upgrading the chart:

```bash
helm install zerossl-issuer ./helm/zerossl-issuer -f values.yaml
```

## Usage

After installing the ZeroSSL Issuer, you need to create an Issuer or ClusterIssuer resource with your ZeroSSL API credentials.

### Creating an Issuer

```yaml
apiVersion: zerossl.cert-manager.io/v1alpha1
kind: Issuer
metadata:
  name: zerossl-issuer
  namespace: cert-manager
spec:
  apiKey: YOUR_ZEROSSL_API_KEY
  validityDays: 90
  strictDomains: false
  dnsChallenge:
    route53:
      region: us-east-1
      accessKeyID: YOUR_AWS_ACCESS_KEY_ID
      secretAccessKeySecretRef:
        name: aws-secret
        key: secret-access-key
```

### Creating a ClusterIssuer

```yaml
apiVersion: zerossl.cert-manager.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: zerossl-cluster-issuer
spec:
  apiKey: YOUR_ZEROSSL_API_KEY
  validityDays: 90
  strictDomains: false
  dnsChallenge:
    route53:
      region: us-east-1
      accessKeyID: YOUR_AWS_ACCESS_KEY_ID
      secretAccessKeySecretRef:
        name: aws-secret
        key: secret-access-key
```

## Uninstallation

```bash
helm delete zerossl-issuer
```

If you installed the CRDs and want to remove them:

```bash
kubectl delete crd challenges.zerossl.cert-manager.io
kubectl delete crd issuers.zerossl.cert-manager.io
kubectl delete crd clusterissuers.zerossl.cert-manager.io
``` 