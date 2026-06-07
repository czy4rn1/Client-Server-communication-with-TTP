## Documentation of the Server application
import os
import socket
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding


## Setting up the logger, file where the logs are to be saved and it's formatting
logger = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s", "[%Y-%m-%d %H:%M:%S]")
logger.setLevel(logging.INFO)
fh = logging.FileHandler('server_log.log', encoding='utf-8')
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)

ttp_host = "bsk_ttp_service"
ttp_port = 8887
ttp_socket = None


## static function used to receive data of n-bytes for a given connection 
def receive_data(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

## class of the server, used to communicate with the user and ttp
class Server:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 8887
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()
        self.session_key = None
        self.serverID = None
        self.encryptedID = None
        self.x509cert = None

    ## function that allows the server to run continuously, listening on the set-up port, waiting for messages
    def start(self):
        global ttp_socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    while True:
                        try:
                            data = conn.recv(1024)
                            if not data:
                                break
                            self.handle_client(data, conn)
                        except ConnectionResetError:
                            print("Abrupt disconnect detected")
                            break

    ## function used to encrypt a message, that server wants to send to the user using an AES algorithm
    # @param message content of the message encoded in utf-8
    def encrypted_msg(self, message):
        iv = os.urandom(16)
        padder = aes_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        text = encryptor.update(padded_data) + encryptor.finalize()
        return iv + text

    ## function used to decrypt a message, received from the user
    # @param data encrypted message from the user
    def decrypt_msg(self, data):
        iv = data[:16]
        text = data[16:]
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(text) + decryptor.finalize()
        unpadder = aes_padding.PKCS7(128).unpadder()
        try:
            final_data = unpadder.update(padded_data) + unpadder.finalize()
            return final_data.decode('utf-8')
        except ValueError:
            return padded_data.decode('utf-8', errors='ignore')

    ## function responsible for handling the entire process of authenticating both server and user using ttp,
    # or managing the messages received from the user
    # @param data message (request) from the user
    # @conn connection with the user
    def handle_client(self, data, conn):
        global ttp_socket
        if data == b'AUTH_REQUEST':
            logger.info('   Received authentication request')
            if ttp_socket is None:
                ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ttp_socket.connect((ttp_host, ttp_port))

            ttp_socket.sendall(data)
            logger.info('   Request sent forward to TTP')

            encID_len = len(self.encryptedID)
            ttp_socket.sendall(encID_len.to_bytes(4, byteorder='big'))
            ttp_socket.sendall(self.encryptedID)

            cert_pem = self.x509cert.public_bytes(serialization.Encoding.PEM)
            ttp_socket.sendall(len(cert_pem).to_bytes(4, byteorder='big'))
            ttp_socket.sendall(cert_pem)
            response = receive_data(ttp_socket, 7)
            if response == b'AUTH_OK':
                logger.info('   Server has been correctly authenticated')
                conn.sendall(response)
                response = receive_data(ttp_socket, 9)
                if response == b'USER_AUTH':
                    logger.info('   Sent information about User Authentication to User')
                    conn.sendall(response)
                    response = receive_data(conn, 17)
                    if response == b'USER_AUTH_REQUEST':
                        logger.info('   Received authentication request from the User')
                        ttp_socket.sendall(response)
                        user_raw_encID_len = receive_data(conn, 4)
                        if user_raw_encID_len:
                            user_encID_len = int.from_bytes(user_raw_encID_len, byteorder='big')
                            user_encID = receive_data(conn, user_encID_len)
                            ttp_socket.sendall(user_encID_len.to_bytes(4, byteorder='big'))
                            ttp_socket.sendall(user_encID)
                            logger.info('   Sent Users encrypted ID forward to TTP')
                        else:
                            logger.error('  AUTHENTICATION FAILED')
                            ttp_socket.close()
                            ttp_socket = None
                            conn.sendall(b'-------ERROR')
                            return
                        user_raw_cert_len = receive_data(conn, 4)
                        if user_raw_cert_len:
                            user_cert_len = int.from_bytes(user_raw_cert_len, byteorder='big')
                            user_cert_pem = receive_data(conn, user_cert_len)
                            ttp_socket.sendall(user_cert_len.to_bytes(4, byteorder='big'))
                            ttp_socket.sendall(user_cert_pem)
                            logger.info('   Sent Users x509 certificate forward to TTP')
                        else:
                            logger.error('  AUTHENTICATION FAILED')
                            ttp_socket.close()
                            ttp_socket = None
                            conn.sendall(b'-------ERROR')
                            return
                        final_response = receive_data(ttp_socket, 12)
                        if final_response == b'USER_AUTH_OK':
                            logger.info('   User has been correctly authenticated')
                            ses_key_len = int.from_bytes(receive_data(ttp_socket, 4), byteorder='big')
                            enc_ses_key = receive_data(ttp_socket, ses_key_len)
                            self.session_key = self.private_key.decrypt(enc_ses_key,
                                                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                                     algorithm=hashes.SHA256(),
                                                                                     label=None))
                            logger.info('   Obtained session key')
                            user_raw_ses_key_len = receive_data(ttp_socket, 4)
                            user_ses_key_len = int.from_bytes(user_raw_ses_key_len, byteorder='big')
                            user_enc_ses_key = receive_data(ttp_socket, user_ses_key_len)
                            conn.sendall(final_response)
                            conn.sendall(user_raw_ses_key_len)
                            conn.sendall(user_enc_ses_key)
                        else:
                            logger.error('  USER AUTHENTICATION FAILED')
                            conn.sendall(b'-------ERROR')
                    else:
                        logger.error('  UNEXPECTED RESPONSE. AUTHENTICATION FAILED')
                        ttp_socket.sendall(b'------------ERROR')
                else:
                    logger.error('  UNEXPECTED RESPONSE. AUTHENTICATION FAILED')
                    conn.sendall(b'----ERROR')
            else:
                logger.error('  SERVER AUTHENTICATION FAILED')
                conn.sendall(b'--ERROR')

            ttp_socket.close()
            ttp_socket = None
        elif data != b'':
            received_text = self.decrypt_msg(data)
            logger.info('   Decrypted message: ' + received_text)
            print(received_text)
            conn.sendall(self.encrypted_msg('Server has received your message'.encode('utf-8')))
            logger.info('   Sent message to the user: Server has received your message')


    ## function to generate server's ID using SHA256 algorithm
    def generate_id(self):
        self.serverID = hashes.Hash(hashes.SHA256())
        self.serverID.update("Server1".encode())
        self.serverID = self.serverID.finalize()

    ## function used to encrypt self-generated id with ttp's public key and obtaining x509 certificate signed by the ttp
    def encrypt_id_and_obtain_x509cert(self):
        global ttp_socket
        ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ttp_socket.connect((ttp_host, ttp_port))
        ttp_socket.sendall(b'server_login')
        logger.info('   Logging in to TTP')
        ttp_key_length = receive_data(ttp_socket, 4)
        ttp_key_length = int.from_bytes(ttp_key_length, byteorder='big')
        ttp_key = b''
        while len(ttp_key) < ttp_key_length:
            data = ttp_socket.recv(ttp_key_length - len(ttp_key))
            if not data: break
            ttp_key += data

        ttp_public_key = serialization.load_pem_public_key(ttp_key)
        logger.info('   Received TTP Public Key')
        self.encryptedID = ttp_public_key.encrypt(self.serverID,
                                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(),
                                                               label=None))
        logger.info('   Encrypted my generated ID with TTP Public Key')
        ttp_socket.sendall(b'X509_REQUEST')
        logger.info('   Sent request for a x509 certificate')
        encID_len = len(self.encryptedID)
        ttp_socket.sendall(encID_len.to_bytes(4, byteorder='big'))
        ttp_socket.sendall(self.encryptedID)
        logger.info('   Sent my encrypted ID')

        public_pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ttp_socket.sendall(len(public_pem).to_bytes(4, byteorder='big'))
        ttp_socket.sendall(public_pem)
        logger.info('   Sent my Public Key')

        raw_cert_len = receive_data(ttp_socket, 4)
        if raw_cert_len:
            cert_len = int.from_bytes(raw_cert_len, byteorder='big')
            cert_pem = receive_data(ttp_socket, cert_len)
            self.x509cert = x509.load_pem_x509_certificate(cert_pem)
            logger.info('   Obtained x509 certificate')
        else:
            logger.error('  OBTAINING X509 CERTIFICATE FAILED')
        ttp_socket.close()
        ttp_socket = None



if __name__ == '__main__':
    server = Server()
    server.generate_id()
    server.encrypt_id_and_obtain_x509cert()
    server.start()
