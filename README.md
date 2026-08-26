<p>
<img src="https://raw.githubusercontent.com/dns3l/dns3l/refs/heads/master/dns3l.svg" alt="dns3l logo" width="200"/>
</p>

# dns3l-certmgr-issuer

The dns3l-certmgr-issuer is an external issuer for cert-manager that uses DNS3L as the source for certificates.


## Installation

First install the cert-manager as described [here](https://cert-manager.io/docs/installation). Certificate requests
are not auto approved by the issuer. To enable auto approval, make sure to let cert-manager auto approve
DNS3L issuer certificate requests by adding the following flags to the cert-manager helm deployment:

```bash
--set approveSignerNames[0]="issuers.cert-manager.io/*" \
--set approveSignerNames[1]="clusterissuers.cert-manager.io/*" \
\
--set approveSignerNames[2]="issuers.dns3l.github.io/*" \
--set approveSignerNames[3]="clusterissuers.dns3l.github.io/*"
```

> More on the approval mechanism [here](https://cert-manager.io/docs/usage/certificaterequest/#approval)


Then there are multiple ways to install the dns3l-certmgr-issuer:

1. Install via packaged helm chart:

```bash
helm install dns3l-certmgr-issuer oci://ghcr.io/dns3l/charts/dns3l-certmgr-issuer --version <version>
```

2. Install via helm chart from source:

```bash
git clone github.com/dns3l/dns3l-certmgr-issuer.git
cd dns3l-certmgr-issuer
make helm-deploy IMG=ghcr.io/dns3l/dns3l-certmgr-issuer:latest
```

3. Install via manifests from source:

```bash
make deploy IMG=ghcr.io/dns3l/dns3l-certmgr-issuer:latest
```

## Usage (dns3l2kube tool)

After successful installation of the controller, you can use the `tools/dns3l2kube` tool to create
an issuer and create your first certificate:

```
tools/dns3l2kube issuer dns3l-example https://dns3l.example.com example-ca
dns3lcli crt claim example-ca example.com
tools/dns3l2kube keycert dns3l-example example-ca example.com example-cert
```

For more information, see the [dns3l2kube docs](./tools/README.md).

## Usage (manual CRDs)

If you have used `dns3l2kube` like above, you can omit this step. Once the controller
is up and running we first need to create a `ClusterIssuer` or `Issuer`
resource that points to the a DNS3L instance. The following example shows an `Issuer`:

```yaml
apiVersion: dns3l.github.io/v1alpha1
kind: Issuer
metadata:
  name: dns3l-example
spec:
  url: https://dns3l.example.com
  caid: example-ca
```

Next it is important that the dns3l-certmgr-issuer **cannot be used to CREATE certificates**. It can only be used to renew certificates
which previously have been created by DNS3L. To introduce the certificate to the k8s cluster, follow the steps below:

1. Create a certificate in DNS3L and download the certificate and private key.

2. Create a secret in the k8s cluster with the certificate and private key:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
    name: example-cert
    annotations:
        cert-manager.io/issuer-name: dns3l-example
        cert-manager.io/issuer-kind: Issuer
        cert-manager.io/issuer-group: dns3l.github.io
        cert-manager.io/certificate-name: example-cert
type: kubernetes.io/tls
data:
    tls.crt: $(base64 -w 0 tls.crt)
    tls.key: $(base64 -w 0 tls.key)
EOF
```

3. Create a `Certificate` resource that points to the secret created in the previous step:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
    name: example-cert
spec:
    secretName: example-cert

    privateKey:
        algorithm: RSA
        size: 2048
        encoding: PKCS1
        rotationPolicy: Never

    commonName: example.com

    issuerRef:
        name: dns3l-example
        kind: Issuer
        group: dns3l.github.io
```

Hereby following things must match:

- The `secretName` in the `Certificate` resource must match the name of the secret created in step 2.
- The `commonName` in the `Certificate` resource must match the common name of the certificate created in DNS3L.
- The `issuerRef` in the `Certificate` resource must match the name and kind of the `Issuer` resource.
- The `cert-manager.io/certificate-name` annotation in the secret must match the name of the `Certificate` resource.
- The `privateKey` spec must match the private key of the certificate created in DNS3L.
- The `rotationPolicy` must be set to `Never` since the private key is not known to the issuer and cannot be rotated.
