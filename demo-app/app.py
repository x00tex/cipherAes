from flask import Flask, request, jsonify
from faker import Faker
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)
_SECRET = b"098f6bcd4621d373cade4e832627b4f6"
SECRET_KEY = _SECRET
IV = _SECRET[:16]
fake = Faker()

def encrypt_aes(plain_text):
    """AES/CBC/PKCS7Padding"""

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()    
    encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    return encrypted_data_base64

def decrypt_aes(encrypted_data):
    """AES/CBC/PKCS7Padding"""

    encrypted_data = base64.b64decode(encrypted_data)    
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return decrypted_data.decode('utf-8')

@app.route('/enc', methods=['GET'])
def random_encrypted():
    try:
        random_phrase = fake.sentence()  # Generate a random sentence
        encrypted_data = encrypt_aes(random_phrase)
        return jsonify({'encrypted_data': encrypted_data, 'Decrypted': random_phrase, 'SECRET_KEY':str(SECRET_KEY), 'IV':str(IV)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/enc', methods=['POST'])
def encrypt_data():
    try:
        json_data = request.get_json()
        plain_text = json_data['data']        
        encrypted_data = encrypt_aes(plain_text)        
        return jsonify({'encrypted_data': encrypted_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
@app.route('/dec', methods=['POST'])
def decrypt_data():
    try:
        json_data = request.get_json()
        encrypted_data = json_data['data']        
        decrypted_data = decrypt_aes(encrypted_data)
        return jsonify({'decrypted_data': decrypted_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
