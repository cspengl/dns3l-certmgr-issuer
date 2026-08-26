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
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"

	dns3lissuerapi "github.com/dns3l/dns3l-certmgr-issuer/api/v1alpha1"
	dns3lclient "github.com/dns3l/dns3l-certmgr-issuer/internal/client"
)

// Issuer reconciles a DNS3LIssuer object
type Issuer struct {
	client.Client
	Scheme *runtime.Scheme
}

const issuerName = "dns3l-issuer.dns3l.github.io"

// +kubebuilder:rbac:groups=dns3l.github.io,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=dns3l.github.io,resources=issuers/status;issuers/status,verbs=patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch

// SetupWithManager sets up the controller with the Manager.
func (i *Issuer) SetupWithManager(mgr ctrl.Manager) error {
	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&dns3lissuerapi.Issuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&dns3lissuerapi.ClusterIssuer{}},

		FieldOwner:       issuerName,
		MaxRetryDuration: 1 * time.Minute,

		Sign:  i.FetchCertificate,
		Check: i.Check,

		EventRecorder: mgr.GetEventRecorder(issuerName),
	}).SetupWithManager(context.Background(), mgr)
}

func (i Issuer) Check(ctx context.Context, issuer issuerapi.Issuer) error {
	dns3lIssuer, err := getDNS3LIssuer(issuer)
	if err != nil {
		return err
	}

	dns3lClient, err := dns3lclient.NewClient(dns3lIssuer.URL)
	if err != nil {
		return err
	}

	_, err = dns3lClient.GetCA(ctx, dns3lIssuer.CAID)
	return err
}

func (i Issuer) FetchCertificate(ctx context.Context, cr signer.CertificateRequestObject, issuer issuerapi.Issuer) (signer.PEMBundle, error) {
	logger := logs.FromContext(ctx, issuerName)

	dns3lIssuer, err := getDNS3LIssuer(issuer)
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

	commonName, err := getCommonName(crDetails.CSR)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	crtName := getDNS3LCrtName(commonName)

	logger.Info("fetching certificate from DNS3L",
		"certificate", crtName,
		"ca", dns3lIssuer.CAID,
		"url", dns3lIssuer.URL,
	)

	chain, err := dns3lClient.GetCertificatePEMChain(ctx, dns3lIssuer.CAID, crtName)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	bundle, err := pki.ParseSingleCertificateChainPEM([]byte(chain))
	if err != nil {
		return signer.PEMBundle{}, err
	}

	return signer.PEMBundle(bundle), nil
}

func getDNS3LCrtName(commonName string) string {
	if strings.HasPrefix(commonName, "*.") {
		// wildcard cert names are without the * in dns3l
		return commonName[2:]
	}
	return commonName
}

func getCommonName(csrPEM []byte) (string, error) {
	csrDER := csrPEM
	pemBlock, _ := pem.Decode(csrPEM)
	if pemBlock != nil {
		csrDER = pemBlock.Bytes
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return "", err
	}

	return csr.Subject.CommonName, nil
}

func getDNS3LIssuer(issuer issuerapi.Issuer) (*dns3lissuerapi.IssuerSpec, error) {
	switch t := issuer.(type) {
	case *dns3lissuerapi.Issuer:
		return &t.Spec, nil
	case *dns3lissuerapi.ClusterIssuer:
		return &t.Spec, nil
	default:
		return nil, signer.PermanentError{
			Err: fmt.Errorf("unexpected issuer type: %t", issuer),
		}
	}
}
