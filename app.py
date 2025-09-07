# app.py
from flask import Flask, render_template, request, send_file, jsonify
from PIL import Image
import stepic
import io
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'temp_uploads'

# Create upload folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_data(data, password):
    salt = os.urandom(16)
    key, salt = self.generate_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return salt + encrypted_data  # Prepend salt to encrypted data

def decrypt_data(encrypted_data, password):
    try:
        salt = encrypted_data[:16]
        actual_encrypted_data = encrypted_data[16:]
        key, _ = generate_key(password, salt)
        f = Fernet(key)
        return f.decrypt(actual_encrypted_data)
    except Exception:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    try:
        # Get uploaded files and form data
        image_file = request.files['coverImage']
        secret_type = request.form['secretType']
        use_encryption = 'encryption' in request.form
        password = request.form.get('password', '')
        
        # Read the image
        image = Image.open(image_file.stream)
        
        # Prepare data to encode
        if secret_type == 'text':
            secret_data = request.form['secretText'].encode('utf-8')
        else:  # file
            secret_file = request.files['secretFile']
            file_data = secret_file.read()
            # Prepend filename to data
            filename = secret_file.filename.encode('utf-8')
            secret_data = len(filename).to_bytes(4, 'big') + filename + file_data
        
        # Encrypt if requested
        if use_encryption:
            if not password:
                return jsonify({'error': 'Password required for encryption'})
            secret_data = encrypt_data(secret_data, password)
        
        # Encode data into image
        encoded_image = stepic.encode(image, secret_data)
        
        # Save to bytes buffer
        img_io = io.BytesIO()
        encoded_image.save(img_io, 'PNG')
        img_io.seek(0)
        
        # Convert to base64 for sending to frontend
        img_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')
        
        return jsonify({
            'success': True,
            'image': f"data:image/png;base64,{img_base64}",
            'filename': f"encoded_{image_file.filename.split('.')[0]}.png"
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/decode', methods=['POST'])
def decode():
    try:
        # Get uploaded file and form data
        stego_image = request.files['stegoImage']
        use_decryption = 'decryption' in request.form
        password = request.form.get('decryptPassword', '')
        
        # Read the image
        image = Image.open(stego_image.stream)
        
        # Decode the data
        decoded_data = stepic.decode(image)
        
        # Decrypt if requested
        if use_decryption:
            if not password:
                return jsonify({'error': 'Password required for decryption'})
            decrypted_data = decrypt_data(decoded_data, password)
            if decrypted_data is None:
                return jsonify({'error': 'Decryption failed. Wrong password?'})
            decoded_data = decrypted_data
        
        # Try to detect if it's a file
        result = {}
        try:
            # Check if data has file header (filename length + filename)
            if len(decoded_data) >= 4:
                filename_len = int.from_bytes(decoded_data[:4], 'big')
                if filename_len > 0 and len(decoded_data) >= 4 + filename_len:
                    filename = decoded_data[4:4+filename_len].decode('utf-8')
                    file_data = decoded_data[4+filename_len:]
                    
                    # Save file to temp location
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                    
                    result['file'] = filename
                    result['file_url'] = f"/download/{filename}"
                    result['message'] = f"File: {filename} ({len(file_data)} bytes)"
        except:
            pass
        
        # If not a file, try to decode as text
        if 'message' not in result:
            try:
                text_data = decoded_data.decode('utf-8')
                result['message'] = text_data
            except UnicodeDecodeError:
                result['message'] = f"Binary data (size: {len(decoded_data)} bytes)"
                # Offer to save as file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decoded_data.bin')
                with open(file_path, 'wb') as f:
                    f.write(decoded_data)
                result['file'] = 'decoded_data.bin'
                result['file_url'] = "/download/decoded_data.bin"
        
        return jsonify({'success': True, **result})
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(
        os.path.join(app.config['UPLOAD_FOLDER'], filename),
        as_attachment=True
    )

if __name__ == '__main__':
    app.run(debug=True)