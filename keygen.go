package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

func load_cert(file string) *x509.Certificate {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	pem_block, _ := pem.Decode(data)
	cer, err := x509.ParseCertificate(pem_block.Bytes)
	if err != nil {
		panic(err)
	}
	return cer
}

func load_key(file string) *rsa.PrivateKey {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	pem_block, _ := pem.Decode(data)
	key, err := x509.ParsePKCS1PrivateKey(pem_block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func load_public_key(file string) any {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	pem_block, _ := pem.Decode(data)
	key, err := x509.ParsePKIXPublicKey(pem_block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func load_csr_from_json(file string) TlsCertRequest {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	var req TlsCertRequest
	err = json.Unmarshal(data, &req)
	if err != nil {
		panic(err)
	}
	return req
}

func create_cert_from_csr(csr TlsCertRequest) x509.Certificate {
	var out x509.Certificate
	out.Subject = csr.Subject
	out.DNSNames = csr.DNSNames
	out.IPAddresses = csr.IPAddresses
	out.IsCA = csr.IsCA
	out.BasicConstraintsValid = csr.BasicConstraintsValid
	if csr.NotAfterHours != 0 {
		out.NotAfter = time.Now().Add(time.Hour * time.Duration(csr.NotAfterHours))
	}
	return out
}

func sign_json_csr(csr_name string, pubkey_name string, out_name string, ca_cert_name string) {
	csr := load_csr_from_json(csr_name)
	template := create_cert_from_csr(csr)
	var ca_cert *x509.Certificate
	if len(ca_cert_name) > 0 {
		ca_cert = load_cert(ca_cert_name)
	}
	ca_key := load_key("ca-private.pem")
	key := load_public_key(pubkey_name)
	template.SerialNumber = big.NewInt(100)
	template.NotBefore = time.Now()
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(time.Hour * 24 * 700)
	}
	if ca_cert == nil {
		ca_cert = &template
	}
	cert_bytes, err := x509.CreateCertificate(rand.Reader, &template, ca_cert, key, ca_key)
	if err != nil {
		panic(err)
	}
	store_cert(out_name, cert_bytes)
}

func test() {
	//sign_json_csr("test.csr.json", "server-public.pem", "test1")
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
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:      true,
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
		DNSNames:     []string{"mm.local"},
		IPAddresses:  []net.IP{net.IPv4(1,2,3,4), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 700),
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
		DNSNames:     []string{"mm.local"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 700),
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
