import datetime
import secrets
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import socket

ttp_socket = None
host = "0.0.0.0"
port = 8887


def receive_data(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


class TTP:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()

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
                        public_pem = self.public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        pub_len = len(public_pem)
                        conn.sendall(pub_len.to_bytes(4, byteorder='big'))
                        conn.sendall(public_pem)
                    elif data.startswith(b'AUTH_REQUEST'):
                        session_key = secrets.token_bytes(32)
                        raw_encID_len = receive_data(conn, 4)
                        if raw_encID_len:
                            encID_len = int.from_bytes(raw_encID_len, byteorder='big')
                            encID = receive_data(conn, encID_len)
                        raw_cert_len = receive_data(conn, 4)
                        if raw_cert_len:
                            cert_len = int.from_bytes(raw_cert_len, byteorder='big')
                            cert_pem = receive_data(conn, cert_len)
                            x509cert = x509.load_pem_x509_certificate(cert_pem)
                            try:
                                self.public_key.verify(x509cert.signature, x509cert.tbs_certificate_bytes,
                                                       padding.PKCS1v15(), x509cert.signature_hash_algorithm)
                                conn.sendall(b'AUTH_OK')
                                conn.sendall(b'USER_AUTH')
                                response = receive_data(conn, 17)
                                if response == b'USER_AUTH_REQUEST':
                                    user_raw_encID_len = receive_data(conn, 4)
                                    if user_raw_encID_len:
                                        user_encID_len = int.from_bytes(user_raw_encID_len, byteorder='big')
                                        user_encID = receive_data(conn, user_encID_len)
                                    user_raw_cert_len = receive_data(conn, 4)
                                    if user_raw_cert_len:
                                        user_cert_len = int.from_bytes(user_raw_cert_len, byteorder='big')
                                        user_cert_pem = receive_data(conn, user_cert_len)
                                        user_x509cert = x509.load_pem_x509_certificate(user_cert_pem)
                                        try:
                                            self.public_key.verify(user_x509cert.signature,
                                                                   user_x509cert.tbs_certificate_bytes,
                                                                   padding.PKCS1v15(),
                                                                   user_x509cert.signature_hash_algorithm)
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
                                            conn.sendall(len(server_enc_ses_key).to_bytes(4, byteorder='big'))
                                            conn.sendall(server_enc_ses_key)
                                            conn.sendall(len(user_enc_ses_key).to_bytes(4, byteorder='big'))
                                            conn.sendall(user_enc_ses_key)

                                        except Exception as e:
                                            print(e)
                            except Exception as e:
                                print(e)
                    elif data == b'X509_REQUEST':
                        self.handle(conn)
    def handle(self, conn):
        try:
            raw_id_len = receive_data(conn, 4)
            if not raw_id_len: return
            id_len = int.from_bytes(raw_id_len, byteorder='big')
            encID = receive_data(conn, id_len)
            raw_pub_len = receive_data(conn, 4)
            if not raw_pub_len: return
            pub_len = int.from_bytes(raw_pub_len, byteorder='big')
            client_pub_pem = receive_data(conn, pub_len)

            encID_bytes = self.private_key.decrypt(encID, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
            client_id_hex = encID_bytes.hex()
            client_pub_key = serialization.load_pem_public_key(client_pub_pem)
            cert = self.create_x509(client_id_hex, client_pub_key)

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            conn.sendall(len(cert_pem).to_bytes(4, byteorder='big'))
            conn.sendall(cert_pem)
        except Exception as e:
            print(e)

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
