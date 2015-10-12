openssl genrsa -out rsa/src/main/resources/private.pem 4096
openssl rsa -in rsa/src/main/resources/private.pem -outform PEM -pubout -out rsa/src/main/resources/public.pem
echo 'Hallo Decrypto lib' |
openssl rsautl -encrypt -pubin -inkey rsa/src/main/resources/public.pem > cypher.dat