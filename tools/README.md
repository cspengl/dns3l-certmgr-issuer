# Tools for the dns3l issuer

## dns3l2kube

This is a light-weight shell script which creates Kubernetes
YAML resources from DNS3L objects.

```
$ tools/dns3l2kube
Usage: dns3l2kube <issuer|keycert>. Type command to see its usage.
```

All commands create Kubernetes resources. They can be either
piped to a file, or you can directly apply them:

```
tools/dns3l2kube [your command args] | kubectl apply -f -
```

### issuer

Creates a new cert-manager issuer.

```
$ tools/dns3l2kube issuer
Usage: dns3l2kube issuer <k8s-issuer-name> <dns3l-url> <dns3l-caid>
```

Arguments:

* `k8s-issuer-name`: Pick a name that your new Kubernetes
    issuer shall get
* `dns3l-url`: This is the URL of your DNS3L instance
    the issuer shall use to connect to.
* `dns3l-caid` The DNS3L CA ID that shall be used on
    the given DNS3L instance. You can get a list of CAs
    with the command `dns3lcli ca list` and pick the ID from
    the returned list. Note that an issuer only supports one
    CA ID at a time, to support multiple ones, create multiple
    issuers with dns3l2kube.

Example:

```
tools/dns3l2kube issuer my-new-issuer https://dns3l.foo.bar le
```

returns

```yaml
apiVersion: dns3l.github.io/v1alpha1
kind: Issuer
metadata:
  name: my-new-issuer
spec:
  url: https://dns3l.foo.bar
  caid: le
```

### keycert

Creates a new Kubernetes Secret resource, and a cert-manager
Certificate resource from an existing DNS3L certificate resource.
Requirement: A DNS3L certificate has been already claimed,
and an issuer has been created with the command before


```
$ tools/dns3l2kube keycert
Usage: dns3l2kube keycert <k8s-issuer-name> <dns3l-ca-id> <dns3l-crt-name> <k8s-crt-name> [dns3lcli-extra-args]
```

Arguments:
* `k8s-issuer-name`: The name of you K8s issuer which you have
    created e.g. with the previous `issuer` command.
* `dns3l-ca-id`: The DNS3L CA ID your issuer uses.
* `dns3l-crt-name`: The name of your DNS3L certificate which
    shall be initially created (with the Secret resource) and
    then continuously managed by cert-manager (with the Certificate resource). Use e.g. `dns3lcli crt list` to obtain the certificate name.
* `k8s-crt-name`: The name of your resources in Kubernetes.
* `dns3lcli-extra-args` The command uses dns3lcli to fetch
    certificate resources. You can pass extra arguments
    to dns3lcli, e.g. to pass a cli config or to pass a
    specific server. For details, check out the
    [dns3lcli README.md](https://github.com/dns3l/dns3l-core/blob/master/README.md#dns3lcli-command-line-api-client)

Example:

```
dns3lcli crt claim le ingress.foo.bar 
tools/dns3l2kube keycert my-new-issuer le ingress.foo.bar ingress-cert
```

returns:

```yaml
apiVersion: v1
kind: Secret
metadata:
    name: ingress-cert
    annotations:
        cert-manager.io/issuer-name: my-new-issuer
        cert-manager.io/issuer-kind: Issuer
        cert-manager.io/issuer-group: dns3l.github.io
        cert-manager.io/certificate-name: ingress-cert
type: kubernetes.io/tls
data:
    tls.crt: |
       [base64 stuff]
    tls.key: |
       [base64 stuff]
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
    name: ingress-cert
spec:
    secretName: ingress-cert

    privateKey:
        algorithm: RSA
        size: 2048
        encoding: PKCS1
        rotationPolicy: Never

    commonName: ingress.foo.bar

    issuerRef:
        name: my-new-issuer
        kind: Issuer
        group: dns3l.github.io
```