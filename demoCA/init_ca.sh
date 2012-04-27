#!/bin/bash

rm -rf certs p12 spkac db 
rm -f root.crt privkey.pem .rnd

mkdir certs p12 spkac db

touch db/index.txt
echo 01 > db/serial

openssl req -config ./openssl.cnf -newkey rsa:2048 -days 3650 -x509 -nodes -out root.crt

chmod -R 777 *

/etc/init.d/apache2 restart
