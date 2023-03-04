package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"log"
)


func server(bind_address string, certf, keyf string) {
	log.Printf("tls certificate:%s key %s", certf, keyf)
	cert, err := tls.LoadX509KeyPair(certf, keyf)
	if err != nil {
		panic(err)
	}
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		Rand: rand.Reader,
		ClientAuth: tls.RequestClientCert,
	}
	log.Printf("listen on %s", bind_address)
	listener, err := tls.Listen("tcp", bind_address, &config)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("accepted connection from %s", conn.RemoteAddr())
		tlscon, ok := conn.(*tls.Conn)
		if !ok {
			log.Println("this is not tls connection ???")
			conn.Close()
			continue
		} else {
			log.Printf("got tls connection version:%d handshake_done:%v", tlscon.ConnectionState().Version, tlscon.ConnectionState().HandshakeComplete)
		}
		err = tlscon.Handshake()
		if err != nil {
			log.Println(err)
			tlscon.Close()
			conn.Close()
			continue
		}
		log.Printf("negotiated proto: %s  server_name: %s", tlscon.ConnectionState().NegotiatedProtocol, tlscon.ConnectionState().ServerName)
		log.Printf("tls_version:%d handshake_done:%v", tlscon.ConnectionState().Version, tlscon.ConnectionState().HandshakeComplete)
		peer_certs := tlscon.ConnectionState().PeerCertificates
		for _, peer_cert := range peer_certs {
			log.Printf("remote peer certificate subj: %+v", peer_cert.Subject)
			log.Printf("                      issuer: %+v", peer_cert.Issuer)
			log.Printf("                   algorithm: %s",  peer_cert.PublicKeyAlgorithm.String())
		}
		r := bufio.NewReader(conn)
		for {
			buffer := make([]byte, 1024)
			n, err := r.Read(buffer)
			if err != nil {
				log.Println(err)
				break
			} else {
				log.Println(string(buffer[:n]))
			}
		}
		tlscon.Close()
		conn.Close()
	}
}
