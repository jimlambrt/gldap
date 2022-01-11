package gldap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/stretchr/testify/require"
)

// TestFreePort just returns an available free localhost port
func TestFreePort(t TestingT) int {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// supports WithTestMTLS
func TestGetTLSconfig(t TestingT, opt ...TestOption) (s *tls.Config, c *tls.Config) {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)

	certSubject := pkix.Name{
		Organization:  []string{"Acme, INC."},
		Country:       []string{"US"},
		Province:      []string{""},
		Locality:      []string{"New York"},
		StreetAddress: []string{"Empire State Building"},
		PostalCode:    []string{"10118"},
	}
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber:          genSerialNumber(t),
		Subject:               certSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(err)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPriv.PublicKey, caPriv)
	require.NoError(err)

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	privBytes, err := x509.MarshalPKCS8PrivateKey(caPriv)
	require.NoError(err)
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	cert := &x509.Certificate{
		SerialNumber:          genSerialNumber(t),
		Subject:               certSubject,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	serverCert := genCert(t, ca, caPriv, cert)

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	clientTLSConf := &tls.Config{
		RootCAs: certpool,
	}

	opts := getTestOpts(t, opt...)
	if opts.withMTLS {
		// setup mTLS for certs from the ca
		serverTLSConf.ClientCAs = certpool
		serverTLSConf.ClientAuth = tls.RequireAndVerifyClientCert

		cert := &x509.Certificate{
			SerialNumber:          big.NewInt(2019),
			Subject:               certSubject,
			EmailAddresses:        []string{"mtls.client@example.com"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			SubjectKeyId:          []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		clientCert := genCert(t, ca, caPriv, cert)
		clientTLSConf.Certificates = []tls.Certificate{clientCert}
	}
	// TODO: I think, this has been deprecated, so remove it it works without it
	// serverTLSConf.BuildNameToCertificate()

	return serverTLSConf, clientTLSConf
}

func genCert(t TestingT, ca *x509.Certificate, caPriv interface{}, certTemplate *x509.Certificate) tls.Certificate {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(err)

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, &certPrivKey.PublicKey, caPriv)
	require.NoError(err)

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privBytes, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	require.NoError(err)

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	newCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	require.NoError(err)
	return newCert
}

func genSerialNumber(t TestingT) *big.Int {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)
	return serialNumber
}
