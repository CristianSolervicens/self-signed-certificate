## Project: _self-signed-certificate_

With this project you can create one or more ca-root (Certificate Authorities)
to sign your own certificates, it's useful for Basic AZURE VPN

_For the CA it creates the files:_
* ./CAs/ca-name.crt  (Certificate)
* ./CAs/ca-name.key  (Private Key)

_For Clients it creates:_
* ./ca-name/ca-name.ClientName.pfx (certificat)
* ./ca.name/ca-name.ClientName.thumb (thumbprint or sha1 digest)

**NOTE:**

With the _**.thumb**_ file content you can *revoke* easily client certificates in Azure Portal

---
Based on https://gist.github.com/arehmandev/63dc3e076c7837f79ec78b897133f5b8

---
 **Dependencies:** pip install pyOpenSSL

***
* Author: Cristian Solervicéns
* Language: Python 3.11
***

Hoping it can be useful for someone

Regards

Cristian Solervicéns