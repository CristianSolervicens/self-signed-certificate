## Project: _self-signed-certificate_

With this project you can create one or more ca-root (Certificate Authorities)
to sign your own certificates, it's useful for Basic AZURE VPN

For the CA it creates a: ca.crt and ca.key files

For Clients it creates:
* ./ca-name/ca-name.ClientName.pfx (certificat)
* ./ca.name/ca-name.ClientName.thumb (thumbprint or sha1 digest)

With the _*.thumb*_ file content you can *revoke* easily client certificates in Azure Portal

Based on https://gist.github.com/arehmandev/63dc3e076c7837f79ec78b897133f5b8

***
* Author: Cristian Solervicéns
* Language: Python 3.11
***

Hoping it can be useful for some of you.


Regards

Cristian Solervicéns