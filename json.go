package main

import (
	"crypto/x509/pkix"
	"net"
)

type TlsCertSubject struct {
	CommonName string
}

type TlsCertRequest struct {
	Subject       pkix.Name
	DNSNames      []string
	IPAddresses   []net.IP
	IsCA          bool
	BasicConstraintsValid bool
	NotAfterHours int
}