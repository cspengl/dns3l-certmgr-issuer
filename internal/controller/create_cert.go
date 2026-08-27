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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/logs"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers/signer"

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
		logger := logs.FromContext(ctx, issuerName)

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

		_, err = dns3lClient.GetCertificate(ctx, dns3lIssuer.CAID, crtName)
		if err == nil {
			// Certificate already exists, no need to create it again
			return next(ctx, cr, issuerObject)
		}

		errMsg, ok := err.(dns3lclient.ErrorMessage)
		if !ok || errMsg.Code != 404 {
			// If the error is not a 404, return the error
			return signer.PEMBundle{}, err
		}

		logger.Info("certificate not found, creating new certificate",
			"certificate", crtName,
			"ca", dns3lIssuer.CAID,
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
			return signer.PEMBundle{}, err
		}

		logger.Info("certificate created successfully",
			"certificate", crtName,
			"ca", dns3lIssuer.CAID,
		)

		// Call next middleware
		bundle, err := next(ctx, cr, issuerObject)
		if err != nil {
			// if there was an error delete the created certificate
			delErr := dns3lClient.DeleteCertificate(ctx, dns3lIssuer.CAID, crtName)
			if delErr != nil {
				logger.Error(delErr, "failed to delete certificate after signing error",
					"certificate", crtName,
					"ca", dns3lIssuer.CAID,
				)
			}
			return signer.PEMBundle{}, err
		}

		// If successful, patch keys in CSR and secret
		crtRes, err := dns3lClient.GetCertificatePEM(ctx, dns3lIssuer.CAID, crtName)
		if err != nil {
			return signer.PEMBundle{}, err
		}

		err = c.patchPrivateKeyInSecret(ctx, cr, crtRes)
		if err != nil {
			return signer.PEMBundle{}, err
		}

		err = c.patchCertificateRequestPublicKey(ctx, cr, crtRes)
		if err != nil {
			return signer.PEMBundle{}, err
		}

		return bundle, err
	}
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

	// First fetch certificate by certificate request annotation
	secretName, ok := cr.GetAnnotations()[cmapi.CertificateRequestPrivateKeyAnnotationKey]
	if !ok {
		return errors.New("certificate request does not have a secret name annotation")
	}

	logger.Info("patching private key in secret for certificate request",
		"secret", secretName,
	)

	// Get secret using secret name from certificate request
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
