// kubeconfig resolution: build a cluster-bound driver from a kubeconfig context,
// the same file kubectl reads. Auth is STATIC only — a bearer token or a client
// certificate. exec / auth-provider plugins (gke-gcloud-auth-plugin, aws eks
// get-token, oidc) are REFUSED loudly: they shell out to external binaries, which
// makes authentication non-hermetic and the driver's behaviour depend on ambient
// tooling. Fail closed, name the plugin, tell the operator to supply a static
// credential — never silently fall back to an unauthenticated client.
package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
			ClientCertificate     string `yaml:"client-certificate"`
			ClientKey             string `yaml:"client-key"`
			Exec                  any    `yaml:"exec"`
			AuthProvider          any    `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// NewFromKubeconfig builds a driver bound to the named context (or current-context
// when contextName is empty). It refuses exec/auth-provider auth.
func NewFromKubeconfig(path, contextName string) (*Driver, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	ctxName := contextName
	if ctxName == "" {
		ctxName = kc.CurrentContext
	}
	if ctxName == "" {
		return nil, fmt.Errorf("kubeconfig: no context given and no current-context set")
	}
	var clusterName, userName string
	found := false
	for _, c := range kc.Contexts {
		if c.Name == ctxName {
			clusterName, userName = c.Context.Cluster, c.Context.User
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("kubeconfig: context %q not found", ctxName)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	server := ""
	for _, c := range kc.Clusters {
		if c.Name != clusterName {
			continue
		}
		server = c.Cluster.Server
		switch {
		case c.Cluster.CertificateAuthorityData != "":
			pem, err := base64.StdEncoding.DecodeString(c.Cluster.CertificateAuthorityData)
			if err != nil {
				return nil, fmt.Errorf("kubeconfig: bad certificate-authority-data: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("kubeconfig: certificate-authority-data has no usable certificate")
			}
			tlsCfg.RootCAs = pool
		case c.Cluster.CertificateAuthority != "":
			pem, err := os.ReadFile(c.Cluster.CertificateAuthority)
			if err != nil {
				return nil, fmt.Errorf("kubeconfig: reading certificate-authority: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("kubeconfig: certificate-authority has no usable certificate")
			}
			tlsCfg.RootCAs = pool
		case c.Cluster.InsecureSkipTLSVerify:
			tlsCfg.InsecureSkipVerify = true
		}
		break
	}
	if server == "" {
		return nil, fmt.Errorf("kubeconfig: cluster %q for context %q has no server", clusterName, ctxName)
	}

	token := ""
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		if u.User.Exec != nil {
			return nil, fmt.Errorf("kubeconfig: user %q uses an exec credential plugin — refused "+
				"(non-hermetic; supply a static token or client certificate instead)", userName)
		}
		if u.User.AuthProvider != nil {
			return nil, fmt.Errorf("kubeconfig: user %q uses an auth-provider plugin — refused "+
				"(non-hermetic; supply a static token or client certificate instead)", userName)
		}
		switch {
		case u.User.Token != "":
			token = u.User.Token
		case u.User.TokenFile != "":
			b, err := os.ReadFile(u.User.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("kubeconfig: reading tokenFile: %w", err)
			}
			token = strings.TrimSpace(string(b))
		case u.User.ClientCertificateData != "" && u.User.ClientKeyData != "":
			cert, key, err := decodeCertKeyData(u.User.ClientCertificateData, u.User.ClientKeyData)
			if err != nil {
				return nil, err
			}
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				return nil, fmt.Errorf("kubeconfig: client key pair: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{pair}
		case u.User.ClientCertificate != "" && u.User.ClientKey != "":
			pair, err := tls.LoadX509KeyPair(u.User.ClientCertificate, u.User.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("kubeconfig: client key pair: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{pair}
		default:
			return nil, fmt.Errorf("kubeconfig: user %q has no static credential (token or client cert)", userName)
		}
		break
	}

	d := &Driver{
		Server:      strings.TrimRight(server, "/"),
		BearerToken: token,
		ClusterID:   server,
		HTTP:        &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		Now:         time.Now,
		Mappings:    embeddedMappings,
	}
	// the production driver enforces the drift guard against the live cluster
	// schema; the test constructor leaves this nil (reads unfingerprinted).
	d.SchemaFetch = d.fetchOpenAPISchema
	return d, nil
}

func decodeCertKeyData(certB64, keyB64 string) ([]byte, []byte, error) {
	cert, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, nil, fmt.Errorf("kubeconfig: bad client-certificate-data: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("kubeconfig: bad client-key-data: %w", err)
	}
	return cert, key, nil
}
