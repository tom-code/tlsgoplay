package main

import (
	"crypto/x509/pkix"
	"net"
)


type TlsCertRequest struct {
	Subject       pkix.Name
	DNSNames      []string
	IPAddresses   []net.IP
	IsCA          bool
	BasicConstraintsValid bool
	NotAfterHours int
}
