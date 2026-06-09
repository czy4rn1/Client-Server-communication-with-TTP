## Documentation of the TTP application
import datetime
import secrets
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import socket

## Setting up the logger, file where the logs are to be saved and it's formatting
logger = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s", "[%Y-%m-%d %H:%M:%S]")
logger.setLevel(logging.INFO)
fh = logging.FileHandler('ttp_log.log', encoding='utf-8')
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)

ttp_socket = None
host = "0.0.0.0"
port = 8887


## static function used to receive data of n-bytes for a given connection 
def receive_data(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


## class of the ttp, used to communicate with the user and server, creating x509 certificates
class TTP:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()

    ## function that allows the ttp to run continuously, listening on the set-up port, waiting for messages from server and user
    def start(self):
        global ttp_socket
        ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ttp_socket.bind((host, port))
        ttp_socket.listen()
        while True:
            conn, addr = ttp_socket.accept()
            with conn:
                while True:
                    data = conn.recv(12)
                    if not data:
                        break
                    if data == b'client_login' or data == b'server_login':
                        if data == b'client_login':
                            logger.info('   User has logged in to TTP')
                        elif data == b'server_login':
                            logger.info('   Server has logged in to TTP')
                        public_pem = self.public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        pub_len = len(public_pem)
                        conn.sendall(pub_len.to_bytes(4, byteorder='big'))
                        conn.sendall(public_pem)
                        logger.info('   TTP has sent its Public Key')
                    elif data.startswith(b'AUTH_REQUEST'):
                        logger.info('   Received authentication request. Authenticating the server')
                        session_key = secrets.token_bytes(32)
                        raw_encID_len = receive_data(conn, 4)
                        if raw_encID_len:
                            encID_len = int.from_bytes(raw_encID_len, byteorder='big')
                            encID = receive_data(conn, encID_len)
                            logger.info('   Received Servers encrypted ID')
                        else:
                            logger.error('  AUTHENTICATION FAILED')
                            conn.sendall(b'---ERROR')
                            continue
                        raw_cert_len = receive_data(conn, 4)
                        if raw_cert_len:
                            cert_len = int.from_bytes(raw_cert_len, byteorder='big')
                            cert_pem = receive_data(conn, cert_len)
                            x509cert = x509.load_pem_x509_certificate(cert_pem)
                            logger.info('   Received Servers x509 certificate')
                            try:
                                self.public_key.verify(x509cert.signature, x509cert.tbs_certificate_bytes,
                                                       padding.PKCS1v15(), x509cert.signature_hash_algorithm)
                                encID_bytes = self.private_key.decrypt(encID, padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                ))
                                server_id_hex = encID_bytes.hex()
                                cert_subject_id_attr = x509cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                                if not cert_subject_id_attr:
                                    logger.error('  SERVER AUTHENTICATION FAILED')
                                    conn.sendall(b'--ERROR')
                                    continue
                                id_from_cert = cert_subject_id_attr[0].value
                                if server_id_hex != id_from_cert:
                                    logger.error('  SERVER AUTHENTICATION FAILED')
                                    conn.sendall(b'--ERROR')
                                    continue

                                conn.sendall(b'AUTH_OK')
                                logger.info('   Server has been correctly authenticated')
                                conn.sendall(b'USER_AUTH')
                                logger.info('   Authenticating the User')
                                response = receive_data(conn, 17)
                                if response == b'USER_AUTH_REQUEST':
                                    logger.info('   Received User authentication request')
                                    user_raw_encID_len = receive_data(conn, 4)
                                    if user_raw_encID_len:
                                        user_encID_len = int.from_bytes(user_raw_encID_len, byteorder='big')
                                        user_encID = receive_data(conn, user_encID_len)
                                        logger.info('   Received Users encrypted ID')
                                    else:
                                        logger.error('  AUTHENTICATION FAILED')
                                        conn.sendall(b'-------ERROR')
                                        continue
                                    user_raw_cert_len = receive_data(conn, 4)
                                    if user_raw_cert_len:
                                        user_cert_len = int.from_bytes(user_raw_cert_len, byteorder='big')
                                        user_cert_pem = receive_data(conn, user_cert_len)
                                        user_x509cert = x509.load_pem_x509_certificate(user_cert_pem)
                                        logger.info('   Received Users x509 certificate')
                                        try:
                                            self.public_key.verify(user_x509cert.signature,
                                                                   user_x509cert.tbs_certificate_bytes,
                                                                   padding.PKCS1v15(),
                                                                   user_x509cert.signature_hash_algorithm)
                                            user_encID_bytes = self.private_key.decrypt(user_encID, padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(),
                                                label=None
                                            ))
                                            user_id_hex = user_encID_bytes.hex()
                                            user_cert_subject_attr = user_x509cert.subject.get_attributes_for_oid(
                                                x509.oid.NameOID.COMMON_NAME)
                                            if not user_cert_subject_attr:
                                                logger.error('  USER AUTHENTICATION FAILED')
                                                conn.sendall(b'-------ERROR')
                                                continue
                                            user_id_from_cert = user_cert_subject_attr[0].value
                                            if user_id_hex != user_id_from_cert:
                                                logger.error('  USER AUTHENTICATION FAILED')
                                                conn.sendall(b'-------ERROR')
                                                continue

                                            server_enc_ses_key = x509cert.public_key(). \
                                                encrypt(session_key,
                                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(),
                                                                     label=None))
                                            user_enc_ses_key = user_x509cert.public_key(). \
                                                encrypt(session_key,
                                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(),
                                                                     label=None))
                                            conn.sendall(b'USER_AUTH_OK')
                                            logger.info('   User has been correctly authenticated')
                                            conn.sendall(len(server_enc_ses_key).to_bytes(4, byteorder='big'))
                                            conn.sendall(server_enc_ses_key)
                                            conn.sendall(len(user_enc_ses_key).to_bytes(4, byteorder='big'))
                                            logger.info('   Sent encrypted session key to Server and User')
                                            conn.sendall(user_enc_ses_key)
                                        except Exception as e:
                                            logger.error('  USER X509 CERTIFICATE VERIFICATION FAILED')
                                            conn.sendall(b'-------ERROR')
                                            print(e)
                                            continue
                                    else:
                                        logger.error('  AUTHENTICATION FAILED')
                                        conn.sendall(b'-------ERROR')
                                        continue
                                else:
                                    logger.error('  UNEXPECTED RESPONSE. AUTHENTICATION FAILED')
                                    conn.sendall(b'-------ERROR')
                                    continue
                            except Exception as e:
                                logger.error('  SERVER X509 CERTIFICATE VERIFICATION FAILED')
                                conn.sendall(b'--ERROR')
                                print(e)
                                continue
                        else:
                            logger.error('  AUTHENTICATION FAILED')
                            conn.sendall(b'--ERROR')
                            continue
                    elif data == b'X509_REQUEST':
                        logger.info('   Received x509 certificate request')
                        self.handle(conn)
                    else:
                        logger.error('  UNEXPECTED MESSAGE')

    ## function used to handle x509 requests from server and user
    # @param conn connection with server or user
    def handle(self, conn):
        try:
            raw_id_len = receive_data(conn, 4)
            if not raw_id_len: return
            id_len = int.from_bytes(raw_id_len, byteorder='big')
            encID = receive_data(conn, id_len)
            logger.info('   Received encrypted ID')
            raw_pub_len = receive_data(conn, 4)
            if not raw_pub_len: return
            pub_len = int.from_bytes(raw_pub_len, byteorder='big')
            client_pub_pem = receive_data(conn, pub_len)
            logger.info('   Received Public Key')

            encID_bytes = self.private_key.decrypt(encID, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
            client_id_hex = encID_bytes.hex()
            client_pub_key = serialization.load_pem_public_key(client_pub_pem)
            cert = self.create_x509(client_id_hex, client_pub_key)
            logger.info('   Created and signed clients x509 certificate')
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            conn.sendall(len(cert_pem).to_bytes(4, byteorder='big'))
            conn.sendall(cert_pem)
            logger.info('   Sent x509 certificate')
        except Exception as e:
            conn.sendall(b'ERROR')
            print(e)

    ## function used to creating and signing x509 certificates
    # @param client_id_hex client's encrypted ID in hex
    # @param client_pub_key client's public key
    def create_x509(self, client_id_hex, client_pub_key):
        client = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id_hex)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TTP")])

        cert = x509.CertificateBuilder().subject_name(client).issuer_name(issuer).public_key(client_pub_key). \
            serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()). \
            not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=2)). \
            sign(self.private_key, hashes.SHA256())
        return cert


if __name__ == '__main__':
    ttp = TTP()
    ttp.start()
