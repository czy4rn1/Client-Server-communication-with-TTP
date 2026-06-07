## Documentation of the Client application
import datetime
import os
import logging
import socket
from guizero import App, Text, TextBox, PushButton
from screeninfo import get_monitors
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography import x509
from cryptography.x509.oid import NameOID

## Setting up the logger and it's formatting
logger = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s", "[%Y-%m-%d %H:%M:%S]")
logger.setLevel(logging.INFO)

##Setting up server and ttp sockets
server_host = os.getenv('BSK_SERVER_IP', '127.0.0.1')
server_port = int(os.getenv('BSK_SERVER_PORT', 8887))

ttp_host = os.getenv('BSK_TTP_IP', '127.0.0.1')
ttp_port = int(os.getenv('BSK_TTP_PORT', 8888))

logged_in_ttp = False
auth_valid = True
signed_in = False
server_socket = None

## static function used to receive data of n-bytes for a given connection 
def receive_data(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

## class that allows to print logs in a TextBox of a guizero app window
class GuizeroHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        log_entry = self.format(record)
        self.text_widget.enable()
        self.text_widget.append(log_entry)
        self.text_widget.disable()

## class of the user, used to communicate with the server and ttp
class Client:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()
        self.clientID = None
        self.encryptedID = None
        self.session_key = None
        self.x509cert = None

    ## function to generate user's ID using SHA256 algorithm
    def generate_id(self):
        self.clientID = hashes.Hash(hashes.SHA256())
        self.clientID.update("Client1".encode())
        self.clientID = self.clientID.finalize()

    ## function used to encrypt a message, that user wants to send to the server using an AES algorithm
    # @param message content of the message encoded in utf-8
    def encrypted_msg(self, message):
        ## @var iv initialization vector - 16 bytes
        iv = os.urandom(16)
        padder = aes_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        text = encryptor.update(padded_data) + encryptor.finalize()
        return iv + text

    ## function used to decrypt a message, received from the server
    # @param data encrypted message from the server
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

    ## function used to encrypt self-generated id with ttp's public key and obtaining x509 certificate signed by the ttp
    def encrypt_id_and_obtain_x509cert(self):
        global logged_in_ttp
        ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ttp_socket.connect((ttp_host, ttp_port))
        ttp_socket.sendall(b'client_login')
        logger.info('   Logged in to TTP')
        ttp_key_length = receive_data(ttp_socket, 4)
        ttp_key_length = int.from_bytes(ttp_key_length, byteorder='big')
        ttp_key = b''
        while len(ttp_key) < ttp_key_length:
            data = ttp_socket.recv(ttp_key_length - len(ttp_key))
            if not data: break
            ttp_key += data

        ttp_public_key = serialization.load_pem_public_key(ttp_key)
        logger.info('   Received TTP Public Key')
        ## encrypting the ID with ttp's public key
        self.encryptedID = ttp_public_key.encrypt(self.clientID,
                                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(),
                                                               label=None))
        logger.info('   Encrypted my ID with TTP Public Key')
        ttp_socket.sendall(b'X509_REQUEST')
        encID_len = len(self.encryptedID)
        ttp_socket.sendall(encID_len.to_bytes(4, byteorder='big'))
        ttp_socket.sendall(self.encryptedID)
        logger.info('   Sent my encrypted ID to TTP')

        public_pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ttp_socket.sendall(len(public_pem).to_bytes(4, byteorder='big'))
        ttp_socket.sendall(public_pem)
        logger.info('   Sent my Public Key to TTP')

        raw_cert_len = receive_data(ttp_socket, 4)
        if raw_cert_len:
            cert_len = int.from_bytes(raw_cert_len, byteorder='big')
            cert_pem = receive_data(ttp_socket, cert_len)
            self.x509cert = x509.load_pem_x509_certificate(cert_pem)
            logger.info('   Obtained x509 certificate')
        ttp_socket.close()
        ttp_socket = None
        logged_in_ttp = True

## function responsible for the graphic user interface
def gui(client: Client):
    ## changing color of a button
    def hoverSend():
        button.bg = "#28d9e0"
    ## changing color of a button
    def unhoverSend():
        button.bg = "#c7c7c7"
    ## function responsible for signing in to the service provided by the server consisting of all the steps of authentication process,
    # or sending an encrypted message to the server, depending on the client's state
    def submit():
        global logged_in_ttp
        global signed_in
        global server_socket
        global auth_valid
        if not signed_in:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_host, server_port))
            ## if it's the first time signing in to the service, user must encrypt their id and obtain x509 certificate from ttp
            if not logged_in_ttp:
                client.encrypt_id_and_obtain_x509cert()
                logged_in_ttp = True
            ## begin authentication of both user and server
            server_socket.sendall(b'AUTH_REQUEST')
            logger.info('   Sent authentication request')
            response = receive_data(server_socket, 7)
            if response == b'AUTH_OK':
                logger.info('   Server has been correctly authenticated')
                response = receive_data(server_socket, 9)
                if response == b'USER_AUTH':
                    logger.info('   User has received request from TTP for User Authentication')
                    server_socket.sendall(b'USER_AUTH_REQUEST')
                    logger.info('   User has sent a request for User Authentication')

                    encID_len = len(client.encryptedID)
                    server_socket.sendall(encID_len.to_bytes(4, byteorder='big'))
                    server_socket.sendall(client.encryptedID)

                    #subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake_name")])
                    #bad_cert = x509.CertificateBuilder(). \
                    #    subject_name(subject). \
                    #    issuer_name(issuer). \
                    #    public_key(client.public_key). \
                    #    serial_number(x509.random_serial_number()). \
                    #    not_valid_before(datetime.datetime.utcnow()). \
                    #    not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1)). \
                    #    sign(client.private_key, hashes.SHA256())
                    #bad_cert_pem = bad_cert.public_bytes(serialization.Encoding.PEM)

                    cert_pem = client.x509cert.public_bytes(serialization.Encoding.PEM)
                    server_socket.sendall(len(cert_pem).to_bytes(4, byteorder='big'))
                    server_socket.sendall(cert_pem)

                    ## HYPOTHETICAL SITUATION, WHERE AN ATTACKER HAS FORGED HIS OWN X509 CERTIFICATE
                    #server_socket.sendall(len(bad_cert_pem).to_bytes(4, byteorder='big'))
                    #server_socket.sendall(bad_cert_pem)

                    final_response = receive_data(server_socket, 12)
                    if final_response == b'USER_AUTH_OK':
                        logger.info('   User has been correctly authenticated')
                        ses_key_len = int.from_bytes(receive_data(server_socket, 4), byteorder='big')
                        enc_ses_key = receive_data(server_socket, ses_key_len)
                        client.session_key = client.private_key.decrypt(enc_ses_key,
                                                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                                     algorithm=hashes.SHA256(),
                                                                                     label=None))
                        logger.info('   Obtained session key')
                        auth_valid = True
                    else:
                        logger.error('   USER AUTHENTICATION FAILED')
                        auth_valid = False
                else:
                    logger.error('   UNEXPECTED RESPONSE. AUTHENTICATION FAILED')
                    auth_valid = False
            else:
                logger.error('   SERVER AUTHENTICATION FAILED')
                auth_valid = False

            if auth_valid:
                intro_text.clear()
                intro_text.append("\nSend data to the server\n")
                box.show()
                space.show()
                button.text = "Send data"
                signed_in = True
        else:
            submitted_data = box.value.encode('utf-8')
            text_data = box.value
            box.clear()
            if submitted_data != b'':
                server_socket.sendall(client.encrypted_msg(submitted_data))
                logger.info('   Sent message to the server: ' + text_data)
                received = client.decrypt_msg(receive_data(server_socket, 48))
                logger.info('   Message from the server: ' + received)
                intro_text.clear()
                intro_text.append("\nLog in to the service\n")
                box.hide()
                space.hide()
                button.text = "Sign in"
                signed_in = False
                msgSent = Text(app, text="Message has been sent", color="#38F527")
                msgSent.after(5000, msgSent.destroy)

    ## setting up the window size, text boxes, buttons and texts of the gui
    monitors = get_monitors()
    m = monitors[0]
    app = App(title="Client", bg="#3B3B3B")
    app.height = round(m.height * 0.4)
    app.width = round(m.width * 0.4)

    intro_text = Text(app, text="\nLog in to the service\n", color="white")

    box = TextBox(app, width=round(app.width / 20))
    box.bg = "white"
    box.hide()

    space = Text(app, text="\n")
    space.hide()

    button = PushButton(app, text="Sign in")
    button.bg = "#C7C7C7"

    Text(app, text="\n")

    button.when_mouse_enters = hoverSend
    button.when_mouse_leaves = unhoverSend
    button.when_clicked = submit

    console_logs = TextBox(app, multiline=True, scrollbar=True, width="fill", height="fill")
    console_logs.bg = "black"
    console_logs.text_color = "white"
    console_logs.font = "Arial"
    console_logs.disable()

    gh = GuizeroHandler(console_logs)
    gh.setLevel(logging.INFO)
    gh.setFormatter(formatter)
    logger.addHandler(gh)
    logger.info('   App started')

    app.display()


if __name__ == '__main__':
    client = Client()
    client.generate_id()
    gui(client)
