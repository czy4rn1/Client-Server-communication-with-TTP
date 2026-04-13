import os
import socket
from guizero import App, Text, TextBox, PushButton
from screeninfo import get_monitors
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography import x509

server_host = "127.0.0.1"
server_port = 8887

ttp_host = "127.0.0.1"
ttp_port = 8888

logged_in_ttp = False
signed_in = False
server_socket = None

def receive_data(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


class Client:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()
        self.clientID = None
        self.encryptedID = None
        self.session_key = None
        self.x509cert = None

    def generate_id(self):
        self.clientID = hashes.Hash(hashes.SHA256())
        self.clientID.update("Client1".encode())
        self.clientID = self.clientID.finalize()

    def encrypted_msg(self, message):
        iv = os.urandom(16)
        padder = aes_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        text = encryptor.update(padded_data) + encryptor.finalize()
        return iv + text

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

    def encrypt_id_and_obtain_x509cert(self):
        global logged_in_ttp
        ttp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ttp_socket.connect((ttp_host, ttp_port))
        ttp_socket.sendall(b'client_login')
        ttp_key_length = receive_data(ttp_socket, 4)
        ttp_key_length = int.from_bytes(ttp_key_length, byteorder='big')
        ttp_key = b''
        while len(ttp_key) < ttp_key_length:
            data = ttp_socket.recv(ttp_key_length - len(ttp_key))
            if not data: break
            ttp_key += data

        ttp_public_key = serialization.load_pem_public_key(ttp_key)
        self.encryptedID = ttp_public_key.encrypt(self.clientID,
                                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(),
                                                               label=None))
        ttp_socket.sendall(b'X509_REQUEST')
        encID_len = len(self.encryptedID)
        ttp_socket.sendall(encID_len.to_bytes(4, byteorder='big'))
        ttp_socket.sendall(self.encryptedID)

        public_pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ttp_socket.sendall(len(public_pem).to_bytes(4, byteorder='big'))
        ttp_socket.sendall(public_pem)

        raw_cert_len = receive_data(ttp_socket, 4)
        if raw_cert_len:
            cert_len = int.from_bytes(raw_cert_len, byteorder='big')
            cert_pem = receive_data(ttp_socket, cert_len)
            self.x509cert = x509.load_pem_x509_certificate(cert_pem)
        ttp_socket.close()
        ttp_socket = None
        logged_in_ttp = True



def gui(client: Client):
    def hoverSend():
        button.bg = "#28d9e0"

    def unhoverSend():
        button.bg = "#c7c7c7"


    def submit():
        global logged_in_ttp
        global signed_in
        global server_socket
        if not signed_in:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_host, server_port))
            if not logged_in_ttp:
                client.encrypt_id_and_obtain_x509cert()
                logged_in_ttp = True
            server_socket.sendall(b'AUTH_REQUEST')
            response = receive_data(server_socket, 7)
            if response == b'AUTH_OK':
                response = receive_data(server_socket, 9)
                if response == b'USER_AUTH':
                    server_socket.sendall(b'USER_AUTH_REQUEST')

                    encID_len = len(client.encryptedID)
                    server_socket.sendall(encID_len.to_bytes(4, byteorder='big'))
                    server_socket.sendall(client.encryptedID)

                    cert_pem = client.x509cert.public_bytes(serialization.Encoding.PEM)
                    server_socket.sendall(len(cert_pem).to_bytes(4, byteorder='big'))
                    server_socket.sendall(cert_pem)

                    final_response = receive_data(server_socket, 12)
                    if final_response == b'USER_AUTH_OK':
                        ses_key_len = int.from_bytes(receive_data(server_socket, 4), byteorder='big')
                        enc_ses_key = receive_data(server_socket, ses_key_len)
                        client.session_key = client.private_key.decrypt(enc_ses_key,
                                                                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                                     algorithm=hashes.SHA256(),
                                                                                     label=None))

            intro_text.clear()
            intro_text.append("\nSend data to the server\n")
            box.show()
            space.show()
            button.text = "Send data"
            signed_in = True
        else:
            submitted_data = box.value.encode('utf-8')
            box.clear()
            if submitted_data != b'':
                server_socket.sendall(client.encrypted_msg(submitted_data))
                received = client.decrypt_msg(receive_data(server_socket, 48))
                print(received)
                intro_text.clear()
                intro_text.append("\nLog in to the service\n")
                box.hide()
                space.hide()
                button.text = "Sign in"
                signed_in = False
                msgSent = Text(app, text="Message has been sent", color="#38F527")
                msgSent.after(5000, msgSent.destroy)


    monitors = get_monitors()
    m = monitors[0]
    app = App(title="Client", bg="#3B3B3B")
    app.height = round(m.height * 0.3)
    app.width = round(m.width * 0.2)

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
    app.display()


if __name__ == '__main__':
    client = Client()
    client.generate_id()
    gui(client)
