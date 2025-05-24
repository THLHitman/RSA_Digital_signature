from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
import os
import json
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from werkzeug.utils import secure_filename
import zipfile
import io

app = Flask(__name__)
app.secret_key = 'rsa-digital-signature-secret-key'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Folders
UPLOAD_FOLDER = 'uploads'
SIGNED_FOLDER = 'signed_files'
KEYS_FOLDER = 'keys'
RECEIVED_FOLDER = 'received_files'
USER_KEYS_FOLDER = 'user_keys'

for folder in [UPLOAD_FOLDER, SIGNED_FOLDER, KEYS_FOLDER, RECEIVED_FOLDER, USER_KEYS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

class RSADigitalSignature:
    def __init__(self):
        self.sender_private_key = None
        self.sender_public_key = None
        self.receiver_private_key = None
        self.receiver_public_key = None
        self.setup_keys()

    def setup_keys(self):
        sender_private_path = os.path.join(KEYS_FOLDER, 'sender_private.pem')
        sender_public_path = os.path.join(KEYS_FOLDER, 'sender_public.pem')
        receiver_private_path = os.path.join(KEYS_FOLDER, 'receiver_private.pem')
        receiver_public_path = os.path.join(KEYS_FOLDER, 'receiver_public.pem')

        if not (os.path.exists(sender_private_path) and os.path.exists(sender_public_path)):
            self.generate_sender_keys()
        else:
            self.load_sender_keys()

        if not (os.path.exists(receiver_private_path) and os.path.exists(receiver_public_path)):
            self.generate_receiver_keys()
        else:
            self.load_receiver_keys()

    def generate_sender_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(os.path.join(KEYS_FOLDER, 'sender_private.pem'), 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))

        with open(os.path.join(KEYS_FOLDER, 'sender_public.pem'), 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        self.sender_private_key = private_key
        self.sender_public_key = public_key

    def generate_receiver_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(os.path.join(KEYS_FOLDER, 'receiver_private.pem'), 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))

        with open(os.path.join(KEYS_FOLDER, 'receiver_public.pem'), 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        self.receiver_private_key = private_key
        self.receiver_public_key = public_key

    def load_sender_keys(self):
        with open(os.path.join(KEYS_FOLDER, 'sender_private.pem'), 'rb') as f:
            self.sender_private_key = load_pem_private_key(f.read(), password=None)
        with open(os.path.join(KEYS_FOLDER, 'sender_public.pem'), 'rb') as f:
            self.sender_public_key = load_pem_public_key(f.read())

    def load_receiver_keys(self):
        with open(os.path.join(KEYS_FOLDER, 'receiver_private.pem'), 'rb') as f:
            self.receiver_private_key = load_pem_private_key(f.read(), password=None)
        with open(os.path.join(KEYS_FOLDER, 'receiver_public.pem'), 'rb') as f:
            self.receiver_public_key = load_pem_public_key(f.read())

    def sign_file(self, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()
        file_hash = hashlib.sha256(file_data).digest()
        signature = self.sender_private_key.sign(
            file_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return base64.b64encode(signature).decode('utf-8'), file_hash.hex()

    def verify_signature(self, file_path, signature_b64):
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            file_hash = hashlib.sha256(file_data).digest()
            signature = base64.b64decode(signature_b64)
            self.sender_public_key.verify(
                signature, file_hash,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return True, file_hash.hex()
        except Exception as e:
            return False, str(e)

rsa_system = RSADigitalSignature()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sender')
def sender():
    return render_template('sender.html')

@app.route('/receiver')
def receiver():
    return render_template('receiver.html')

@app.route('/create_user_keys', methods=['GET'])
def generate_keys():
    return render_template('generate_keys.html')

@app.route('/create_user_keys', methods=['POST'])
def create_user_keys():
    username = request.form.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'Vui lòng nhập tên người dùng'})

    user_folder = os.path.join(USER_KEYS_FOLDER, username)
    os.makedirs(user_folder, exist_ok=True)

    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(os.path.join(user_folder, 'private.pem'), 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))

        with open(os.path.join(user_folder, 'public.pem'), 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        return jsonify({'success': True, 'message': f'Đã tạo khóa cho người dùng {username}!'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Lỗi: {str(e)}'})

@app.route('/sign_file', methods=['POST'])
def sign_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Không có file được chọn'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Không có file được chọn'})

    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        signature, file_hash = rsa_system.sign_file(file_path)

        signed_info = {
            'filename': filename,
            'signature': signature,
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            'file_size': os.path.getsize(file_path),
            'status': 'signed'
        }

        info_path = os.path.join(SIGNED_FOLDER, f"{filename}.info")
        with open(info_path, 'w') as f:
            json.dump(signed_info, f, indent=2)

        return jsonify({'success': True, 'message': f'File {filename} đã được ký thành công!',
                        'signature': signature[:50] + '...', 'hash': file_hash})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Lỗi: {str(e)}'})

@app.route('/verify_file', methods=['POST'])
def verify_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Không có file được chọn'})

    file = request.files['file']
    signature = request.form.get('signature', '')

    if not signature:
        return jsonify({'success': False, 'message': 'Vui lòng nhập chữ ký'})

    try:
        filename = secure_filename(file.filename)
        temp_path = os.path.join(RECEIVED_FOLDER, f"temp_{filename}")
        file.save(temp_path)

        is_valid, result = rsa_system.verify_signature(temp_path, signature)

        if is_valid:
            final_path = os.path.join(RECEIVED_FOLDER, filename)
            os.rename(temp_path, final_path)
            return jsonify({'success': True, 'message': 'Chữ ký hợp lệ! File đã được xác thực.',
                            'valid': True, 'hash': result})
        else:
            os.remove(temp_path)
            return jsonify({'success': True, 'message': 'Chữ ký không hợp lệ!',
                            'valid': False, 'error': result})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Lỗi: {str(e)}'})

@app.route('/get_signed_files')
def get_signed_files():
    files = []
    for info_file in os.listdir(SIGNED_FOLDER):
        if info_file.endswith('.info'):
            with open(os.path.join(SIGNED_FOLDER, info_file), 'r') as f:
                file_info = json.load(f)
                files.append(file_info)
    return jsonify({'files': files})

@app.route('/get_received_files')
def get_received_files():
    files = []
    for filename in os.listdir(RECEIVED_FOLDER):
        if not filename.startswith('temp_'):
            path = os.path.join(RECEIVED_FOLDER, filename)
            files.append({'filename': filename,
                          'size': os.path.getsize(path),
                          'timestamp': datetime.fromtimestamp(os.path.getmtime(path)).isoformat()})
    return jsonify({'files': files})

@app.route('/download_file/<path:filename>')
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File không tồn tại", 404

@app.route('/download_received/<path:filename>')
def download_received(filename):
    file_path = os.path.join(RECEIVED_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File không tồn tại", 404

@app.route('/get_signature/<path:filename>')
def get_signature(filename):
    info_path = os.path.join(SIGNED_FOLDER, f"{filename}.info")
    if os.path.exists(info_path):
        with open(info_path, 'r') as f:
            info = json.load(f)
        return jsonify({'signature': info['signature'], 'hash': info['file_hash'], 'timestamp': info['timestamp']})
    return jsonify({'error': 'Không tìm thấy thông tin chữ ký'}), 404

@app.route('/download_signature_info/<path:filename>')
def download_signature_info(filename):
    info_path = os.path.join(SIGNED_FOLDER, f"{filename}.info")
    if os.path.exists(info_path):
        return send_file(info_path, as_attachment=True)
    return "Không tìm thấy file chữ ký", 404

@app.route('/download_keys')
def download_keys():
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for key_file in ['sender_private.pem', 'sender_public.pem', 'receiver_private.pem', 'receiver_public.pem']:
            path = os.path.join(KEYS_FOLDER, key_file)
            if os.path.exists(path):
                zf.write(path, key_file)
    memory_file.seek(0)
    return send_file(io.BytesIO(memory_file.read()), mimetype='application/zip',
                     as_attachment=True, download_name='rsa_keys.zip')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
