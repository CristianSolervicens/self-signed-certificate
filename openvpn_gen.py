# pip install pyOpenSSL
# import hashlib
# import socket

import os
from OpenSSL import crypto, SSL

CA_FOLDER = './CAs'


def find_files(path, patern, depth) -> list:
    from glob import glob
    import fnmatch
    found = []

    if depth == 0:
        return found

    path_x = f'{path}\\**'
    for fo in glob(path_x, recursive=False):
        if os.path.isdir(fo):
            res = find_files(fo, patern, depth - 1)
            found.extend(res)
        else:
            if fnmatch.fnmatch(os.path.basename(fo), patern):
                found.append(fo)
    return found


def clear():
    """
    Limpiar pantalla de la consola
    """
    if os.name == "posix":
        os.system ("clear")
    else:
        os.system ("cls")


def menu(titulo, lista):
    """
    Despliega un menú con los elementos de la lista entregada como parámetro.
        Se agrega el elemento "Salir" como último de la lista.
    Retorna:
        Indice de la lista que corresponde al elemento seleccionado
        -1 = Salir
    """
    clear()
    print(f'\n{titulo}')
    x: int = 0
    for elem in lista:
        print(f"\t{str(x+1 )} - {elem}")
        x += 1
    print(f"\t{str(x+1)} - Salir")

    print("")
    opcion_menu: int = 0
    while True:
        try:
            opcion_menu = int(input("Ingresa el número de la Opción >> "))

            if int(opcion_menu) >= 0 and int(opcion_menu) <= len(lista) + 1:
                # print(f"Opción {str(opcion_menu)}")
                break

        except ValueError:
            print("Ingrese sólo números")

    if int(opcion_menu) == len(lista)+1:
        return -1
    else:
        return int(opcion_menu)-1


def make_keypair(algorithm=crypto.TYPE_RSA, numbits=2048):
    pkey = crypto.PKey()
    pkey.generate_key(algorithm, numbits)
    return pkey

# Creates a certificate signing request (CSR) given the specified subject attributes.
def make_csr(pkey, CN, C=None, ST=None, L=None, O=None, OU=None, emailAddress=None, hashalgorithm='sha256WithRSAEncryption'):
    req = crypto.X509Req()
    req.get_subject()
    subj  = req.get_subject()

    if C:
        subj.C = C
    if ST:
        subj.ST = ST
    if L:
        subj.L = L
    if O:
        subj.O = O
    if OU:
        subj.OU = OU
    if CN:
        subj.CN = CN
    if emailAddress:
        subj.emailAddress = emailAddress

    req.set_pubkey(pkey)
    req.sign(pkey, hashalgorithm)
    return req

# Create a certificate authority (if we need one)
def create_ca(CN, C="", ST="", L="", O="", OU="", emailAddress="", hashalgorithm='sha256WithRSAEncryption'):
    cakey = make_keypair()
    careq = make_csr(cakey, CN=CN)
    cacert = crypto.X509()
    cacert.set_serial_number(0)
    cacert.gmtime_adj_notBefore(0)
    cacert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cacert.set_issuer(careq.get_subject())
    cacert.set_subject(careq.get_subject())
    cacert.set_pubkey(careq.get_pubkey())
    cacert.set_version(2)

    # Set the extensions in two passes
    cacert.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
        crypto.X509Extension(b'subjectKeyIdentifier', True, b'hash', subject=cacert)
    ])

    # ... now we can set the authority key since it depends on the subject key
    cacert.add_extensions([
        crypto.X509Extension(b'authorityKeyIdentifier', False, b'issuer:always, keyid:always', issuer=cacert, subject=cacert)
    ])

    cacert.sign(cakey, hashalgorithm)
    return cacert, cakey


# Create a new slave cert.
def create_slave_certificate(csr, cakey, cacert, serial):
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cert.set_issuer(cacert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_version(2)

    extensions = []
    extensions.append(crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'))

    extensions.append(crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert))
    extensions.append(crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always,issuer:always', subject=cacert, issuer=cacert))

    cert.add_extensions(extensions)
    cert.sign(cakey, 'sha256WithRSAEncryption')

    return cert

# Dumps content to a string
def dump_file_in_mem(material, format=crypto.FILETYPE_PEM):
    dump_func = None
    if isinstance(material, crypto.X509):
        dump_func = crypto.dump_certificate
    elif isinstance(material, crypto.PKey):
        dump_func = crypto.dump_privatekey
    elif isinstance(material, crypto.X509Req):
        dump_func = crypto.dump_certificate_request
    else:
        raise Exception("Don't know how to dump content type to file: %s (%r)" % (type(material), material))

    return dump_func(format, material)


# Loads the file into the appropriate openssl object type.
def load_from_file(materialfile, objtype, format=crypto.FILETYPE_PEM):
    if objtype is crypto.X509:
        load_func = crypto.load_certificate
    elif objtype is crypto.X509Req:
        load_func = crypto.load_certificate_request
    elif objtype is crypto.PKey:
        load_func = crypto.load_privatekey
    else:
        raise Exception("Unsupported material type: %s" % (objtype,))

    with open(materialfile, 'r') as fp:
        buf = fp.read()

    material = load_func(format, buf)
    return material

def retrieve_key_from_file(keyfile):
    return load_from_file(keyfile, crypto.PKey)

def retrieve_csr_from_file(csrfile):
    return load_from_file(csrfile, crypto.X509Req)

def retrieve_cert_from_file(certfile):
    return load_from_file(certfile, crypto.X509)


def make_new_ovpn_file(ca_cert, ca_key, clientname, serial, commonoptspath, filepath):

    # Read our common options file first
    f = open(commonoptspath, 'r')
    common = f.read()
    f.close()

    cacert = retrieve_cert_from_file(ca_cert)
    cakey = retrieve_key_from_file(ca_key)

    # Generate a new private key pair for a new certificate.
    key = make_keypair()
    # Generate a certificate request
    csr = make_csr(key, clientname)
    # Sign the certificate with the new csr
    crt = create_slave_certificate(csr, cakey, cacert, serial)

    # Now we have a successfully signed certificate. We must now
    # create a .ovpn file and then dump it somewhere.
    clientkey = dump_file_in_mem(key)
    clientcert = dump_file_in_mem(crt)
    cacertdump = dump_file_in_mem(cacert)
    ovpn = "%s<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n" % (common, cacertdump, clientcert, clientkey)

    # Write our file.
    with open(filepath, 'w') as f:
        f.write(ovpn)

def create_user_cert(ca, usuario):
    ca_crt = f'{CA_FOLDER}/{ca}.crt'
    ca_key = f'{CA_FOLDER}/{ca}.key'
    cacert = retrieve_cert_from_file(ca_crt)
    cakey = retrieve_key_from_file(ca_key)

    # Generate a new private key pair for a new certificate.
    key = make_keypair()
    # Generate a certificate request
    csr = make_csr(key, usuario)
    # Sign the certificate with the new csr
    crt = create_slave_certificate(csr, cakey, cacert, 2)

    # Now we have a successfully signed certificate. We must now
    # create a .ovpn file and then dump it somewhere.
    # clientkey = dump_file_in_mem(key)
    clientcert = dump_file_in_mem(crt)
    cacertdump = dump_file_in_mem(cacert)

    pfx = crypto.PKCS12()
    pfx.set_privatekey(key)
    pfx.set_certificate(crt)
    pfx.set_ca_certificates([cacert])
    pfx_data = pfx.export()
    thumb_print = crt.digest("sha1").decode("ascii").replace(":", "")
    if not os.path.isdir(ca):
        os.mkdir(ca)

    file_name = f'{ca}.{usuario}'
    with open(f'{ca}/{file_name}.pfx', 'wb') as fh:
        fh.write(pfx_data)

    with open(f'{ca}/{file_name}.thumb', 'w') as fh:
        fh.write(thumb_print)

    return f'{file_name}.pfx'


def crear_nuevo_ca(new_ca_name: str):
    cacert, cakey = create_ca(CN=new_ca_name)
    cacert_dump = dump_file_in_mem(cacert)
    cakey_dump = dump_file_in_mem(cakey)
    with open(f'{CA_FOLDER}/{new_ca_name}.crt', 'wb') as file_handle:
        file_handle.write(cacert_dump)
    with open(f'{CA_FOLDER}/{new_ca_name}.key', 'wb') as file_handle:
        file_handle.write(cakey_dump)
    os.mkdir(new_ca_name)

def cargar_cas() -> list:
    cert_authorities = find_files(CA_FOLDER, '*.crt', 1)
    cert_authorities = [os.path.splitext(os.path.basename(k))[0] for k in cert_authorities]
    cert_authorities.insert(0, 'NUEVO CA')
    return cert_authorities


def main():
    clear()
    print("")
    print("Creación de Certificados para Azure VPN Gateway")
    if not os.path.isdir(CA_FOLDER):
        os.mkdir(CA_FOLDER)

    cert_authorities = cargar_cas()

    if len(cert_authorities) == 1:
        print('No hay Certificadores')
        ca_name = input("CA Name >> ")
        if ca_name.casefold() in [k.casefold() for k in cert_authorities]:
            print(f'Certificador [{ca_name}] ya existe!')
        else:
            crear_nuevo_ca(ca_name)
            cert_authorities = cargar_cas()

    while True:
        ca_id = menu("Seleccione Certificador", cert_authorities)

        if ca_id == -1:
            print("")
            print("Finalizado")
            input(">> ")
            print("")
            return
        ca = cert_authorities[ca_id]

        if ca == 'NUEVO CA':
            ca_name = input("Nuevo CA Name >> ")
            if ca_name.casefold() in [k.casefold() for k in cert_authorities]:
                print(f'Certificador [{ca_name}] ya existe!')
            else:
                crear_nuevo_ca(ca_name)
                cert_authorities = cargar_cas()
        else:
            usuario = input(f"Nuevo Usuario para [{ca}] >> ")
            if usuario == "":
                return

            if os.path.isfile(f'{ca}/{ca}.{usuario}.pfx'):
                res = input("El Certificado ya existe, ¿desea Reemplazarlo? (s/N) >> ").casefold()
                if res not in ['s', 'si']:
                    continue

            cert_name = create_user_cert(ca, usuario)
            print("")
            print(f"Certificado [{cert_name}] Creado")
            print(f"  *** El Archivo [{os.path.splitext(cert_name)[0]}.thumb] Le permitirá Revocar fácilmente el Certificado cuando lo necesite")
            input(">> ")


if __name__ == "__main__":
    # make_new_ovpn_file("ca.crt", "ca.key", "justasictest", 0x0C, "common.txt", "justastictest.ovpn")
    # print("Done")
    main()

