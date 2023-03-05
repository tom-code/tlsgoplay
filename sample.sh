

./tt gen-key ca
./tt gen-key server
./tt create-cert example/ca.csr.json ca-public.pem ca -c ""
./tt create-cert example/server.csr.json server-public.pem server -c ca-cert.pem

openssl verify -verbose -CAfile ca-cert.pem server-cert.pem