"""
    #retrievedCertInfo
    1. 

    #duplicateCerti  (uses 'cryptography' library)
    1. Parse target server cert using "x509.load_pem_x509_certificate()"
    2. Create certi builder object
    2. Set the properties of new certi (including signing rootCA info)
    3. Build the certi
    4. Save the certi in "./certs" using "dump_certificate()"
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import ssl

class DuplicateCerti:
    def generate(server_ssl_socket,targetServer):
    
        # Get the certificate information
        # target_cert=server_ssl_socket.getpeercert()
        # print(target_cert)
        target_cert = ssl.get_server_certificate((targetServer, 443))

        target_cert_info = x509.load_pem_x509_certificate(target_cert.encode(), default_backend())
        # print(target_cert_info.extensions)

        # Load the root CA certificate and key
        with open("./certs/rootCA.pem", "rb") as f:
            root_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open("./certs/rootCA.key", "rb") as f:
            root_ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        # Create a new certificate builder and set the properties of new certi
        builder = x509.CertificateBuilder(
                    issuer_name=root_ca_cert.subject,
                    subject_name=target_cert_info.subject,
                    public_key=root_ca_cert.public_key(),
                    serial_number=target_cert_info.serial_number,
                    not_valid_before=target_cert_info.not_valid_before,
                    not_valid_after=target_cert_info.not_valid_after,
                    extensions=target_cert_info.extensions
                    )

        # Sign the certificate with the root CA private key
        new_cert = builder.sign(private_key=root_ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

        # Save the new certificate
        with open(f"./certs/{targetServer}.pem", "wb") as f:
            f.write(new_cert.public_bytes(encoding=serialization.Encoding.PEM))
