package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

func store_cert(name string, cert_bytes []byte) {
	certBlock := pem.Block {
		Type: "CERTIFICATE",
		Bytes: cert_bytes,
	}
	err := ioutil.WriteFile(name+"-cert.pem", pem.EncodeToMemory(&certBlock), 0600)
	if err != nil {
		panic(err)
	}
}

func generate_and_store_key(name string) *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privPKCS1 := x509.MarshalPKCS1PrivateKey(priv)
	privBlock := pem.Block {
	  Type: "RSA PRIVATE KEY",
	  Bytes: privPKCS1,
	}
	err = ioutil.WriteFile(name+"-private.pem", pem.EncodeToMemory(&privBlock), 0600)
	if err != nil {
	  panic(err)
	}
  
	pubPKIX, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
	  panic(err)
	}
	pubBlock := pem.Block {
	  Type: "PUBLIC KEY",
	  Bytes: pubPKIX,
	}
	err = ioutil.WriteFile(name+"-public.pem", pem.EncodeToMemory(&pubBlock), 0600)
	if err != nil {
	  panic(err)
	}
	return priv
}

func generate_and_store_key_ecdsa(name string) *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	privEC, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	privBlock := pem.Block {
		Type: "EC PRIVATE KEY",
		Bytes: privEC,
	}
	err = ioutil.WriteFile(name+"-private.pem", pem.EncodeToMemory(&privBlock), 0600)
	if err != nil {
		panic(err)
	}
  
	pubPKIX, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	pubBlock := pem.Block {
		Type: "PUBLIC KEY",
		Bytes: pubPKIX,
	}
	err = ioutil.WriteFile(name+"-public.pem", pem.EncodeToMemory(&pubBlock), 0600)
	if err != nil {
		panic(err)
	}
	return priv
}

func generate_and_store_key_ed25519(name string) (*ed25519.PrivateKey, *ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	privEC, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	privBlock := pem.Block {
		Type: "PRIVATE KEY",
		Bytes: privEC,
	}
	err = ioutil.WriteFile(name+"-private.pem", pem.EncodeToMemory(&privBlock), 0600)
	if err != nil {
		panic(err)
	}
  
	return &priv, &pub
}

func keygen() {

	ca_key := generate_and_store_key("ca")
	server_key := generate_and_store_key("server")
	client_key := generate_and_store_key_ecdsa("client")
	ca_template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name {
			CommonName: "my.ca",
		},
		//DNSNames: []string{"ca.com"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 700),	
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA: true,
		BasicConstraintsValid: true,
	}
	ca_cert_bytes, err := x509.CreateCertificate(rand.Reader, &ca_template, &ca_template, &ca_key.PublicKey, ca_key)
	if err != nil {
		panic(err)
	}
	store_cert("ca", ca_cert_bytes)

	cert_template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name {
		  	CommonName: "mm.local",
		},
		DNSNames: []string{"mm.local"},
		IPAddresses:  []net.IP{net.IPv4(1,2,3,4), net.IPv6loopback},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 700),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	cert_bytes, err := x509.CreateCertificate(rand.Reader, &cert_template, &ca_template, &server_key.PublicKey, ca_key)
	store_cert("server", cert_bytes)

	cli_template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name {
		  	CommonName: "client.mm.local",
		},
		DNSNames: []string{"mm.local"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 700),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	cli_bytes, err := x509.CreateCertificate(rand.Reader, &cli_template, &ca_template, &client_key.PublicKey, ca_key)
	if err != nil {
		panic(err)
	}
	store_cert("client", cli_bytes)
}
