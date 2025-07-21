# /ca/Dockerfile
FROM alpine:3.18

RUN apk add --no-cache openssl bash

WORKDIR /ca

COPY entrypoint.sh .
COPY openssl.cnf .

RUN chmod +x entrypoint.sh

VOLUME ["/ca/certs", "/ca/private", "/ca/newcerts", "/ca/csr", "/ca/crl"]

ENTRYPOINT ["./entrypoint.sh"]
