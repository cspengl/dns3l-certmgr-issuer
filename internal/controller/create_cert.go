/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/logs"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"

	dns3lissuerapi "github.com/dns3l/dns3l-certmgr-issuer/api/v1alpha1"
	dns3lclient "github.com/dns3l/dns3l-certmgr-issuer/internal/client"
	dns3lapi "github.com/dns3l/dns3l-core/api/v1"
)

const createCertEnabledEnv = "DNS3L_ISSUER_CREATE_CERT_ENABLED"

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update

func CreateCert(c client.Client) SignMiddleware {
	return func(next signer.Sign) signer.Sign {
		return (&createCertMiddleware{c}).createCert(next)
	}
}

type createCertMiddleware struct {
	client client.Client
}

func (c *createCertMiddleware) createCert(next signer.Sign) signer.Sign {
	return func(ctx context.Context, cr signer.CertificateRequestObject, issuerObject issuerapi.Issuer) (signer.PEMBundle, error) {
		dns3lIssuer, err := getDNS3LIssuer(issuerObject)
		if err != nil {
			return signer.PEMBundle{}, err
		}

		dns3lClient, err := dns3lclient.NewClient(dns3lIssuer.URL)
		if err != nil {
			return signer.PEMBundle{}, err
		}
		crDetails, err := cr.GetCertificateDetails()
		if err != nil {
			return signer.PEMBundle{}, err
		}

		csr, err := getCR(crDetails.CSR)
		if err != nil {
			return signer.PEMBundle{}, err
		}

		crtName := getDNS3LCrtName(csr.Subject.CommonName)

		claimed, err := c.claimIfNotExist(ctx, dns3lClient, dns3lIssuer, cr)
		if err != nil {
			return signer.PEMBundle{}, err
		}

		returnAfterClaim := func(b signer.PEMBundle, err error) (signer.PEMBundle, error) {
			if err == nil || !claimed {
				return b, err
			}

			delErr := dns3lClient.DeleteCertificate(ctx, dns3lIssuer.CAID, crtName)
			if delErr != nil {
				err = errors.Join(fmt.Errorf("failed to delete certificate after error: %w", delErr), err)
			}
			return b, err
		}

		// Call next middleware
		bundle, err := next(ctx, cr, issuerObject)
		if err != nil {
			return returnAfterClaim(bundle, err)
		}

		crtRes, err := dns3lClient.GetCertificatePEM(ctx, dns3lIssuer.CAID, crtName)
		if err != nil {
			return returnAfterClaim(bundle, err)
		}

		// Check if keys need to be patched in CSR and secret
		// Keys must be patched if the key used
		// to sign the CSR is not the same as the key in DNS3L.
		keysMatch, err := c.privateKeysMatch(ctx, cr, crtRes.Key)
		if err != nil {
			return returnAfterClaim(bundle, err)
		}
		if keysMatch {
			return bundle, nil
		}

		err = c.patchCertificateRequestPublicKey(ctx, cr, crtRes)
		if err != nil {
			return returnAfterClaim(bundle, err)
		}

		err = c.patchPrivateKeyInSecret(ctx, cr, crtRes)
		if err != nil {
			return returnAfterClaim(bundle, err)
		}

		return bundle, nil
	}
}

func (c *createCertMiddleware) claimIfNotExist(
	ctx context.Context, dns3lClient *dns3lclient.Client, dns3lIssuer *dns3lissuerapi.IssuerSpec, cr signer.CertificateRequestObject,
) (claimed bool, err error) {
	crDetails, err := cr.GetCertificateDetails()
	if err != nil {
		return false, err
	}

	csr, err := getCR(crDetails.CSR)
	if err != nil {
		return false, err
	}

	crtName := getDNS3LCrtName(csr.Subject.CommonName)

	_, err = dns3lClient.GetCertificate(ctx, dns3lIssuer.CAID, crtName)
	errMsg, ok := err.(dns3lclient.ErrorMessage)
	if !ok || errMsg.Code != 404 {
		// If the error is not a 404, return the error
		return false, err
	}

	logger := logs.FromContext(ctx, issuerName)
	logger.Info("certificate not found, creating new certificate",
		"certificate", crtName,
	)

	// Create certificate
	err = dns3lClient.ClaimCertificate(
		ctx, dns3lIssuer.CAID, &dns3lapi.CertClaimInfo{
			Name:            crtName,
			Wildcard:        strings.HasPrefix(csr.Subject.CommonName, "*."),
			SubjectAltNames: csr.DNSNames,
		},
	)
	if err != nil {
		return false, err
	}

	logger.Info("certificate created successfully",
		"certificate", crtName,
	)

	return true, nil
}

func (c *createCertMiddleware) privateKeysMatch(ctx context.Context, cr signer.CertificateRequestObject, dns3lPrivateKeyPEM string) (bool, error) {
	// Get private key from secret
	privateKey, err := c.getNextPrivateKey(ctx, cr)
	if err != nil {
		return false, err
	}

	// Decode private key from DNS3L
	block, _ := pem.Decode([]byte(dns3lPrivateKeyPEM))
	if block == nil {
		return false, errors.New("failed to decode PEM block containing private key from DNS3L")
	}

	dns3lPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false, err
	}

	// Compare private keys
	equal, err := privateKeysEqual(privateKey, dns3lPrivateKey)
	if err != nil {
		return false, err
	}
	return equal, nil
}

func (c *createCertMiddleware) getNextPrivateKey(ctx context.Context, cr signer.CertificateRequestObject) (crypto.PrivateKey, error) {
	// First get secret name from CertificateRequest annotation
	secretName, ok := cr.GetAnnotations()[cmapi.CertificateRequestPrivateKeyAnnotationKey]
	if !ok {
		return nil, errors.New("certificate request does not have a secret name annotation")
	}

	// Get secret using secret name from CertificateRequest
	var (
		secret corev1.Secret

		secretK8sName = client.ObjectKey{Namespace: cr.GetNamespace(), Name: secretName}
	)
	err := c.client.Get(ctx, secretK8sName, &secret)
	if err != nil {
		return nil, err
	}

	// Get private key from secret
	privateKeyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, errors.New("secret does not contain a private key")
	}

	// Decode private key
	privateKey, err := utilpki.DecodePrivateKeyBytes(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (c *createCertMiddleware) patchCertificateRequestPublicKey(
	ctx context.Context, cr signer.CertificateRequestObject,
	crtRes *dns3lapi.CertResources,
) error {
	logger := logs.FromContext(ctx, issuerName)

	logger.Info("patching public key in certificate request")

	// decode public key
	crt, err := utilpki.DecodeX509CertificateBytes([]byte(crtRes.Certificate))
	if err != nil {
		return err
	}

	var request cmapi.CertificateRequest
	// fetch and decode certificate request
	err = c.client.Get(ctx, client.ObjectKey{Namespace: cr.GetNamespace(), Name: cr.GetName()}, &request)
	if err != nil {
		return err
	}

	csr, err := utilpki.DecodeX509CertificateRequestBytes(request.Spec.Request)
	if err != nil {
		return err
	}

	// Update the public key in the CSR
	csr.PublicKey = crt.PublicKey

	// Encode the updated CSR
	signerKey, err := utilpki.DecodePrivateKeyBytes([]byte(crtRes.Key))
	if err != nil {
		return err
	}

	updatedCSRBytes, err := utilpki.EncodeCSR(csr, signerKey)
	if err != nil {
		return err
	}

	// Update the CertificateRequest with the new CSR
	request.Spec.Request = updatedCSRBytes

	// Update the CertificateRequest in Kubernetes
	err = c.client.Update(ctx, &request)
	if err != nil {
		return err
	}

	return nil
}

func (c *createCertMiddleware) patchPrivateKeyInSecret(
	ctx context.Context, cr signer.CertificateRequestObject, crtRes *dns3lapi.CertResources,
) error {
	logger := logs.FromContext(ctx, issuerName)

	// First get secret name from CertificateRequest annotation
	secretName, ok := cr.GetAnnotations()[cmapi.CertificateRequestPrivateKeyAnnotationKey]
	if !ok {
		return errors.New("certificate request does not have a secret name annotation")
	}

	logger.Info("patching private key in secret for certificate request",
		"secret", secretName,
	)

	// Get secret using secret name from CertificateRequest
	var (
		secret corev1.Secret

		secretK8sName = client.ObjectKey{Namespace: cr.GetNamespace(), Name: secretName}
	)
	err := c.client.Get(ctx, secretK8sName, &secret)
	if err != nil {
		return err
	}

	// Private keys from DNS3L are always PEM and in PKCS1 format,
	// so we need to convert them to PKCS8 format before storing them in the secret
	block, _ := pem.Decode([]byte(crtRes.Key))
	if block == nil {
		return errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	privateKeyEnc, err := utilpki.EncodePrivateKey(privateKey, cmapi.PKCS8)
	if err != nil {
		return err
	}

	// Patch secret with private key
	secret.Data[corev1.TLSPrivateKeyKey] = privateKeyEnc
	err = c.client.Update(ctx, &secret)
	if err != nil {
		return err
	}

	return nil
}

func privateKeysEqual(a, b crypto.PrivateKey) (bool, error) {
	switch priv := a.(type) {
	case *rsa.PrivateKey:
		return priv.Equal(b), nil
	case *ecdsa.PrivateKey:
		return priv.Equal(b), nil
	case ed25519.PrivateKey:
		return priv.Equal(b), nil
	default:
		return false, fmt.Errorf("unrecognised public key type: %T", a)
	}
}
