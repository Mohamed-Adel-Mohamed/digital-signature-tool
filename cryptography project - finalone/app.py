from flask import Flask, render_template, request, jsonify, send_file
import os
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import json
from datetime import datetime
import io
from werkzeug.utils import secure_filename
import tempfile
import mimetypes

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

class DigitalSignatureSystem:
    def __init__(self):
        self.rsa_keys = {}
        self.ecc_keys = {}
        self.signatures = []
    
    def sign_file_rsa(self, file_content, private_key, hash_algorithm='SHA256', use_hash=True):
        """Sign file content with RSA"""
        try:
            if use_hash:
                signature = self.sign_rsa_with_hash(file_content, private_key, hash_algorithm)
                file_hash = base64.b64encode(self.hash_message(file_content, hash_algorithm)).decode('utf-8')
            else:
                # For textbook RSA, convert first few bytes to integer
                if len(file_content) > 8:
                    file_int = int.from_bytes(file_content[:8], byteorder='big')
                else:
                    file_int = int.from_bytes(file_content, byteorder='big')
                signature_int = self.sign_rsa_without_hash(file_int, private_key)
                signature = str(signature_int)
                file_hash = str(file_int)
            
            return signature, file_hash
        except Exception as e:
            raise Exception(f"File signing failed: {str(e)}")
        
    def sign_file_ecc(self, file_content, private_key, hash_algorithm='SHA256'):
        """Sign file content with ECC"""
        try:
            signature = self.sign_ecc(file_content, private_key, hash_algorithm)
            file_hash = base64.b64encode(self.hash_message(file_content, hash_algorithm)).decode('utf-8')
            return signature, file_hash
        except Exception as e:
            raise Exception(f"ECC file signing failed: {str(e)}")



    def verify_file_rsa(self, file_content, signature, public_key, hash_algorithm='SHA256', use_hash=True):
        """Verify RSA file signature"""
        try:
            if use_hash:
                return self.verify_rsa_with_hash(file_content, signature, public_key, hash_algorithm)
            else:
                if len(file_content) > 8:
                    file_int = int.from_bytes(file_content[:8], byteorder='big')
                else:
                    file_int = int.from_bytes(file_content, byteorder='big')
                signature_int = int(signature)
                return self.verify_rsa_without_hash(file_int, signature_int, public_key)
        except Exception as e:
            return False



    def verify_file_ecc(self, file_content, signature, public_key, hash_algorithm='SHA256'):
        """Verify ECC file signature"""
        try:
            return self.verify_ecc(file_content, signature, public_key, hash_algorithm)
        except Exception as e:
            return False


    def get_file_info(self, file_content, filename):
        """Get file information"""
        file_size = len(file_content)
        file_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        
        return {
            'filename': filename,
            'size': file_size,
            'type': file_type,
            'size_readable': self.format_file_size(file_size)
        }


    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"

    # RSA Key Generation
    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'private_pem': private_pem.decode('utf-8'),
            'public_pem': public_pem.decode('utf-8')
        }
    
    # ECC Key Generation
    def generate_ecc_keys(self):
        """Generate ECC key pair using SECP256R1 curve"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'private_pem': private_pem.decode('utf-8'),
            'public_pem': public_pem.decode('utf-8')
        }
    
    

    
    def hash_message(self, message, algorithm='SHA256'):
        """Hash message using specified algorithm"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if algorithm == 'SHA256':
            return hashlib.sha256(message).digest()
        elif algorithm == 'SHA1':
            return hashlib.sha1(message).digest()
        elif algorithm == 'MD5':
            return hashlib.md5(message).digest()
        else:
            raise ValueError("Unsupported hash algorithm")
    
    def sign_rsa_with_hash(self, message, private_key, hash_algorithm='SHA256'):
        """Sign message with RSA using hash function"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Map string to cryptography hash algorithm
        hash_alg_map = {
            'SHA256': hashes.SHA256(),
            'SHA1': hashes.SHA1(),
            'MD5': hashes.MD5()
        }
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_alg_map[hash_algorithm]
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def sign_rsa_without_hash(self, message_int, private_key):
        """Sign integer message with RSA without hash (textbook RSA)"""
        # Get RSA parameters
        private_numbers = private_key.private_numbers()
        d = private_numbers.private_exponent
        n = private_numbers.public_key.n
        
        # Textbook RSA signature: s = m^d mod n
        signature = pow(message_int, d, n)
        return signature
    
    def verify_rsa_without_hash(self, message_int, signature_int, public_key):
        """Verify RSA signature without hash (textbook RSA)"""
        # Get RSA parameters
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n
        
        # Textbook RSA verification: m = s^e mod n
        recovered_message = pow(signature_int, e, n)
        return recovered_message == message_int
    
    def sign_ecc(self, message, private_key, hash_algorithm='SHA256'):
        """Sign message with ECC"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        hash_alg_map = {
            'SHA256': hashes.SHA256(),
            'SHA1': hashes.SHA1(),
            'MD5': hashes.MD5()
        }
        
        signature = private_key.sign(
            message,
            ec.ECDSA(hash_alg_map[hash_algorithm])
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_rsa_with_hash(self, message, signature, public_key, hash_algorithm='SHA256'):
        """Verify RSA signature with hash"""
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            signature_bytes = base64.b64decode(signature)
            
            hash_alg_map = {
                'SHA256': hashes.SHA256(),
                'SHA1': hashes.SHA1(),
                'MD5': hashes.MD5()
            }
            
            public_key.verify(
                signature_bytes,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_alg_map[hash_algorithm]
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def verify_ecc(self, message, signature, public_key, hash_algorithm='SHA256'):
        """Verify ECC signature"""
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            signature_bytes = base64.b64decode(signature)
            
            hash_alg_map = {
                'SHA256': hashes.SHA256(),
                'SHA1': hashes.SHA1(),
                'MD5': hashes.MD5()
            }
            
            public_key.verify(
                signature_bytes,
                message,
                ec.ECDSA(hash_alg_map[hash_algorithm])
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def text_to_number(self, text):
        """Convert text to number (A=01, B=02, etc.)"""
        result = ""
        for char in text.upper():
            if char.isalpha():
                result += str(ord(char) - ord('A') + 1).zfill(2)
        return int(result) if result else 0
    




    def find_message_for_signature(self, target_signature, public_key):
        """Find a message that produces the target signature (for Eve's attack)"""
        # Get RSA parameters
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n
        
        # Calculate message: m = s^e mod n
        message = pow(target_signature, e, n)
        return message

# Initialize the system
signature_system = DigitalSignatureSystem()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    data = request.get_json()
    key_type = data.get('key_type', 'RSA')
    user_id = data.get('user_id', 'default')
    
    try:
        if key_type == 'RSA':
            keys = signature_system.generate_rsa_keys()
            signature_system.rsa_keys[user_id] = keys
        else:  # ECC
            keys = signature_system.generate_ecc_keys()
            signature_system.ecc_keys[user_id] = keys
        
        return jsonify({
            'success': True,
            'public_key': keys['public_pem'],
            'private_key': keys['private_pem']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/sign_message', methods=['POST'])
def sign_message():
    data = request.get_json()
    message = data.get('message', '')
    key_type = data.get('key_type', 'RSA')
    user_id = data.get('user_id', 'default')
    hash_algorithm = data.get('hash_algorithm', 'SHA256')
    use_hash = data.get('use_hash', True)
    
    try:
        if key_type == 'RSA':
            if user_id not in signature_system.rsa_keys:
                return jsonify({'success': False, 'error': 'No RSA keys found for user'})
            
            private_key = signature_system.rsa_keys[user_id]['private_key']
            
            if use_hash:
                signature = signature_system.sign_rsa_with_hash(message, private_key, hash_algorithm)
                message_hash = base64.b64encode(signature_system.hash_message(message, hash_algorithm)).decode('utf-8')
            else:
                # Convert message to integer for textbook RSA
                message_int = signature_system.text_to_number(message) if message.isalpha() else int(message)
                signature_int = signature_system.sign_rsa_without_hash(message_int, private_key)
                signature = str(signature_int)
                message_hash = str(message_int)
        
        else:  # ECC
            if user_id not in signature_system.ecc_keys:
                return jsonify({'success': False, 'error': 'No ECC keys found for user'})
            
            private_key = signature_system.ecc_keys[user_id]['private_key']
            signature = signature_system.sign_ecc(message, private_key, hash_algorithm)
            message_hash = base64.b64encode(signature_system.hash_message(message, hash_algorithm)).decode('utf-8')
        
        # Store signature record
        signature_record = {
            'id': len(signature_system.signatures) + 1,
            'message': message,
            'signature': signature,
            'key_type': key_type,
            'user_id': user_id,
            'hash_algorithm': hash_algorithm,
            'use_hash': use_hash,
            'timestamp': datetime.now().isoformat(),
            'message_hash': message_hash
        }
        signature_system.signatures.append(signature_record)
        
        return jsonify({
            'success': True,
            'signature': signature,
            'message_hash': message_hash,
            'record_id': signature_record['id']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    data = request.get_json()
    message = data.get('message', '')
    signature = data.get('signature', '')
    key_type = data.get('key_type', 'RSA')
    user_id = data.get('user_id', 'default')
    hash_algorithm = data.get('hash_algorithm', 'SHA256')
    use_hash = data.get('use_hash', True)
    
    try:
        if key_type == 'RSA':
            if user_id not in signature_system.rsa_keys:
                return jsonify({'success': False, 'error': 'No RSA keys found for user'})
            
            public_key = signature_system.rsa_keys[user_id]['public_key']
            
            if use_hash:
                is_valid = signature_system.verify_rsa_with_hash(message, signature, public_key, hash_algorithm)
            else:
                message_int = signature_system.text_to_number(message) if message.isalpha() else int(message)
                signature_int = int(signature)
                is_valid = signature_system.verify_rsa_without_hash(message_int, signature_int, public_key)
        
        else:  # ECC
            if user_id not in signature_system.ecc_keys:
                return jsonify({'success': False, 'error': 'No ECC keys found for user'})
            
            public_key = signature_system.ecc_keys[user_id]['public_key']
            is_valid = signature_system.verify_ecc(message, signature, public_key, hash_algorithm)
        
        return jsonify({
            'success': True,
            'is_valid': is_valid
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/eve_attack', methods=['POST'])
def eve_attack():
    data = request.get_json()
    target_signature = int(data.get('target_signature', 112090305))
    user_id = data.get('user_id', 'alice')
    
    try:
        if user_id not in signature_system.rsa_keys:
            return jsonify({'success': False, 'error': 'No RSA keys found for Alice'})
        
        public_key = signature_system.rsa_keys[user_id]['public_key']
        message = signature_system.find_message_for_signature(target_signature, public_key)
        
        # Verify the attack works
        is_valid = signature_system.verify_rsa_without_hash(message, target_signature, public_key)
        
        return jsonify({
            'success': True,
            'message': message,
            'signature': target_signature,
            'is_valid': is_valid,
            'explanation': f"Eve can find message {message} that produces signature {target_signature} by computing m = s^e mod n"
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_signatures')
def get_signatures():
    return jsonify({'signatures': signature_system.signatures})

@app.route('/cryptographic_analysis')
def cryptographic_analysis():
    analysis = {
        'rsa_without_hash_vulnerability': {
            'problem': 'RSA signature forgery without hash',
            'difficulty': 'Solving the RSA problem: given n, e, and s, find m such that m ≡ s^e (mod n)',
            'explanation': 'The difficulty lies in the computational intractability of the RSA problem, not just knowing d. Even without d, finding a valid message-signature pair requires solving the RSA problem, which involves computing discrete logarithms in the multiplicative group Z_n*.',
            'mathematical_foundation': 'The security relies on the difficulty of integer factorization and the RSA assumption.'
        },
        'eve_attack_method': {
            'technique': 'Signature-to-message attack',
            'method': 'Given target signature s, compute m = s^e mod n',
            'why_it_works': 'In textbook RSA without hash, the signature verification is simply checking if m ≡ s^e (mod n). Eve can choose any signature value and compute the corresponding message.',
            'prevention': 'Use cryptographic hash functions and proper padding schemes like PSS.'
        }
    }
    return jsonify(analysis)

@app.route('/sign_file', methods=['POST'])
def sign_file():
    try:
        # Check if file is present in request
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Get form data
        key_type = request.form.get('key_type', 'RSA')
        user_id = request.form.get('user_id', 'default')
        hash_algorithm = request.form.get('hash_algorithm', 'SHA256')
        use_hash = request.form.get('use_hash', 'true').lower() == 'true'
        
        # Read file content
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        # Get file info
        file_info = signature_system.get_file_info(file_content, filename)
        
        if key_type == 'RSA':
            if user_id not in signature_system.rsa_keys:
                return jsonify({'success': False, 'error': 'No RSA keys found for user'})
            
            private_key = signature_system.rsa_keys[user_id]['private_key']
            signature, file_hash = signature_system.sign_file_rsa(
                file_content, private_key, hash_algorithm, use_hash
            )
        
        else:  # ECC
            if user_id not in signature_system.ecc_keys:
                return jsonify({'success': False, 'error': 'No ECC keys found for user'})
            
            private_key = signature_system.ecc_keys[user_id]['private_key']
            signature, file_hash = signature_system.sign_file_ecc(
                file_content, private_key, hash_algorithm
            )
        
        # Store signature record
        signature_record = {
            'id': len(signature_system.signatures) + 1,
            'type': 'file',
            'filename': filename,
            'file_info': file_info,
            'signature': signature,
            'key_type': key_type,
            'user_id': user_id,
            'hash_algorithm': hash_algorithm,
            'use_hash': use_hash if key_type == 'RSA' else True,
            'timestamp': datetime.now().isoformat(),
            'file_hash': file_hash
        }
        signature_system.signatures.append(signature_record)
        
        return jsonify({
            'success': True,
            'signature': signature,
            'file_hash': file_hash,
            'file_info': file_info,
            'record_id': signature_record['id']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/verify_file', methods=['POST'])
def verify_file():
    try:
        # Check if file is present in request
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Get form data
        signature = request.form.get('signature', '')
        key_type = request.form.get('key_type', 'RSA')
        user_id = request.form.get('user_id', 'default')
        hash_algorithm = request.form.get('hash_algorithm', 'SHA256')
        use_hash = request.form.get('use_hash', 'true').lower() == 'true'
        
        if not signature.strip():
            return jsonify({'success': False, 'error': 'No signature provided'})
        
        # Read file content
        file_content = file.read()
        filename = secure_filename(file.filename)
        
        # Get file info
        file_info = signature_system.get_file_info(file_content, filename)
        
        if key_type == 'RSA':
            if user_id not in signature_system.rsa_keys:
                return jsonify({'success': False, 'error': 'No RSA keys found for user'})
            
            public_key = signature_system.rsa_keys[user_id]['public_key']
            is_valid = signature_system.verify_file_rsa(
                file_content, signature, public_key, hash_algorithm, use_hash
            )
        
        else:  # ECC
            if user_id not in signature_system.ecc_keys:
                return jsonify({'success': False, 'error': 'No ECC keys found for user'})
            
            public_key = signature_system.ecc_keys[user_id]['public_key']
            is_valid = signature_system.verify_file_ecc(
                file_content, signature, public_key, hash_algorithm
            )
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'file_info': file_info
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

