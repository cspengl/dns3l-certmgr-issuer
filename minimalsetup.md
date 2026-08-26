# Minimal-dependency locally working setup for development

## Plugin Installation

Install [Kubernetes-in-Docker (kind)](https://kind.sigs.k8s.io/).

Set up the cluster and install cert manager and the DNS3L issuer:

```bash
kind create cluster
helm install \
  cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.21.1 \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true \
  --set approveSignerNames[0]="issuers.cert-manager.io/*" \
  --set approveSignerNames[1]="clusterissuers.cert-manager.io/*" \
  --set approveSignerNames[2]="issuers.dns3l.github.io/*" \
  --set approveSignerNames[3]="clusterissuers.dns3l.github.io/*"
make docker-build
kind load docker-image ghcr.io/dns3l/dns3l-certmgr-issuer:dev
make helm-deploy
```

## Install dns3ld and make it reachable by kind

This can be skipped if you have a working dns3l endpoint available.

Currently, we need to set up `dns3ld` with docker-compose, because it is not supporting
Kubernetes at the moment. Set it up according to https://github.com/dns3l/dns3l-core/blob/master/rampup/README.md, but in the compose.yaml, set the listen address in your dns3ld ports definition to `0.0.0.0`, otherwise the instance is not reachable from both the docker containers and the host itself (note that every host on your network can now access the instance, so use e.g. iptables to block it if necessary).

There is no straightforward way to address the host from the kind containers, so you need
to do some steps to find out the host's `kind`-facing IP, before defining your first issuer:

```bash
# Get the host IP that docker and kind sees, this can be used by the pods.
export HOST_IP_4KIND=$(docker network inspect kind -f '{{(index .IPAM.Config 1).Gateway}}')
export DNS3L_URL_4KIND=http://$HOST_IP_4KIND:8080
echo $DNS3L_URL_4KIND # check that the URL is valid, this is our dns3l endpoint
# Check that containers really can reach the host. YAML info output from the server should be
# returned:
kubectl run curl --rm -it --image=curlimages/curl --restart=Never -- curl $DNS3L_URL_4KIND/api/v1/info
# Finally, create the issuer using the dns3l2kube tool:
tools/dns3l2kube issuer dns3l-test "$DNS3L_URL_4KIND" ca1 | kubectl apply -f -
```

If you want to be sure, check the logs if the dns3l issuer writes `Succeeded checking the issuer`.

## Create the first certificate and import it

For the next step, you need dns3lcli, because `tools/dns3l2kube` requires it.
Create a certificate in DNS3L and let it be maintained by cert-manager:

```bash
# Claim a certificate if not already done
dns3lcli crt claim ca1 foo.bla.example.com --no-auth --server http://127.0.0.1:8080
# Import the claimed certificate to Kubernetes (creates a Secret and a Certificate resource)
tools/dns3l2kube keycert dns3l-test ca1 foo.bla.example.com foobla-cert --no-auth --server http://127.0.0.1:8080 | kubectl apply -f -
```
