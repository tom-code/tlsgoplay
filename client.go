package main

import (
	"crypto/tls"
	"log"
)


func client(address string, certf, keyf string) {
	cert, err := tls.LoadX509KeyPair(certf, keyf)
	if err != nil {
		panic(err)
	}
	tls_conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", address, tls_conf)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	err = conn.Handshake()
	if err != nil {
		panic(err)
	}
	log.Printf("negotiated proto: %s  server_name: %s", conn.ConnectionState().NegotiatedProtocol, conn.ConnectionState().ServerName)
	peer_certs := conn.ConnectionState().PeerCertificates
	for _, peer_cert := range peer_certs {
		log.Printf("remote peer certificate subj: %+v", peer_cert.Subject)
		log.Printf("                      issuer: %+v", peer_cert.Issuer)
		log.Printf("                   algorithm: %s",  peer_cert.PublicKeyAlgorithm.String())
	}
}