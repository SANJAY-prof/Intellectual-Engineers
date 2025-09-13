import os
import logging
import json
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_file, session, abort
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import io
import base64

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', secrets.token_urlsafe(32))

# Security configuration
APP_USERNAME = os.environ.get('APP_USERNAME', 'hsm_admin')
APP_PASSWORD = os.environ.get('APP_PASSWORD', 'secure_hsm_2025!')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Storage for encrypted files and keys
file_storage = {}

class HSMSimulator:
    """Simulates Hardware Security Module operations"""
    
    def __init__(self):
        self.rsa_keypair = None
        self.generate_rsa_keypair()
        
    def generate_rsa_keypair(self):
        """Generate RSA keypair (simulating HSM key generation)"""
        try:
            self.rsa_keypair = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            logger.info("RSA keypair generated successfully")
        except Exception as e:
            logger.error(f"Failed to generate RSA keypair: {e}")
            raise
    
    def get_public_key(self):
        """Get RSA public key for encryption operations"""
        if self.rsa_keypair is None:
            raise RuntimeError("RSA keypair not initialized")
        return self.rsa_keypair.public_key()
    
    def get_private_key(self):
        """Simulate HSM private key access (requires authentication)"""
        if self.rsa_keypair is None:
            raise RuntimeError("RSA keypair not initialized")
        return self.rsa_keypair
    
    def wrap_key(self, aes_key):
        """Wrap AES key using RSA public key (RSA-OAEP)"""
        try:
            public_key = self.get_public_key()
            wrapped_key = public_key.encrypt(
                aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return wrapped_key
        except Exception as e:
            logger.error(f"Key wrapping failed: {e}")
            raise
    
    def unwrap_key(self, wrapped_key):
        """Unwrap AES key using RSA private key (requires HSM access)"""
        private_key = None
        try:
            private_key = self.get_private_key()
            aes_key = private_key.decrypt(
                wrapped_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return aes_key
        except Exception as e:
            logger.error(f"Key unwrapping failed: {e}")
            raise
        finally:
            # Clear sensitive data from local variables
            if private_key is not None:
                del private_key
    
    def get_public_key_pem(self):
        """Export public key in PEM format"""
        public_key = self.get_public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def get_private_key_pem(self):
        """Export private key in PEM format (use with extreme caution)"""
        if self.rsa_keypair is None:
            raise RuntimeError("RSA keypair not initialized")
        
        pem = self.rsa_keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode('utf-8')
    
    def get_key_info(self):
        """Get key information including fingerprint"""
        public_key = self.get_public_key()
        key_size = public_key.key_size
        
        # Generate key fingerprint
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashes.Hash(hashes.SHA256(), backend=default_backend())
        fingerprint.update(pem_bytes)
        fingerprint_hex = fingerprint.finalize().hex()[:16]  # First 16 chars
        
        return {
            'key_size': key_size,
            'fingerprint': fingerprint_hex,
            'algorithm': 'RSA-OAEP'
        }
    

class FileEncryption:
    """Handles file encryption/decryption using AES-GCM"""
    
    @staticmethod
    def generate_aes_key():
        """Generate random 256-bit AES key"""
        return secrets.token_bytes(32)  # 256 bits
    
    @staticmethod
    def encrypt_file(file_data, aes_key):
        """Encrypt file data using AES-256-GCM"""
        try:
            # Generate random IV (96 bits for GCM)
            iv = secrets.token_bytes(12)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt the file
            ciphertext = encryptor.update(file_data) + encryptor.finalize()
            
            # Get authentication tag
            auth_tag = encryptor.tag
            
            logger.info(f"File encrypted with AES-256-GCM (size: {len(file_data)} bytes)")
            return {
                'ciphertext': ciphertext,
                'iv': iv,
                'auth_tag': auth_tag
            }
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            raise
        finally:
            # Clear sensitive data
            if 'aes_key' in locals():
                # Zero out the key (this is a best effort in Python)
                aes_key = b'\x00' * len(aes_key)
    
    @staticmethod
    def decrypt_file(encrypted_data, aes_key):
        """Decrypt file data using AES-256-GCM"""
        try:
            # Create cipher
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(encrypted_data['iv'], encrypted_data['auth_tag']),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt the file
            plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
            
            logger.info(f"File decrypted successfully (size: {len(plaintext)} bytes)")
            return plaintext
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            raise
        finally:
            # Clear sensitive data
            if 'aes_key' in locals():
                aes_key = b'\x00' * len(aes_key)

# Initialize HSM simulator
hsm = HSMSimulator()

def require_auth(f):
    """Decorator to require authentication for sensitive endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if user is authenticated
        if not session.get('authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def sanitize_error(error_msg):
    """Sanitize error messages to prevent information leakage"""
    # Map specific errors to generic messages
    error_map = {
        'cryptography': 'Cryptographic operation failed',
        'unwrap': 'Key operation failed',
        'decrypt': 'Decryption operation failed',
        'encrypt': 'Encryption operation failed',
        'file': 'File operation failed',
        'key': 'Key operation failed'
    }
    
    error_lower = str(error_msg).lower()
    for keyword, generic_msg in error_map.items():
        if keyword in error_lower:
            return generic_msg
    
    return 'Operation failed'

@app.route('/')
def index():
    """Main page with file upload interface"""
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    """Simple login endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request format'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if username == APP_USERNAME and password == APP_PASSWORD:
            session['authenticated'] = True
            session['username'] = username
            return jsonify({'success': True, 'message': 'Authentication successful'})
        else:
            # Log failed login attempt
            logger.warning(f"Failed login attempt for username: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout endpoint"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file():
    """Handle file upload and encryption"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file data
        file_data = file.read()
        filename = file.filename
        
        # Generate AES key
        aes_key = FileEncryption.generate_aes_key()
        
        # Encrypt file with AES-GCM
        encrypted_data = FileEncryption.encrypt_file(file_data, aes_key)
        
        # Wrap AES key with RSA
        wrapped_key = hsm.wrap_key(aes_key)
        
        # Generate unique file ID
        file_id = secrets.token_urlsafe(16)
        
        # Store encrypted file and wrapped key
        file_storage[file_id] = {
            'filename': filename,
            'encrypted_data': encrypted_data,
            'wrapped_key': wrapped_key,
            'upload_time': datetime.now().isoformat()
        }
        
        
        # Clear sensitive data
        aes_key = b'\x00' * len(aes_key)
        del file_data
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': filename,
            'message': 'File encrypted and stored successfully'
        })
        
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        return jsonify({'error': sanitize_error(e)}), 500

@app.route('/api/download/<file_id>')
@require_auth
def download_file(file_id):
    """Download encrypted file (without decryption)"""
    try:
        if file_id not in file_storage:
            return jsonify({'error': 'File not found'}), 404
        
        file_info = file_storage[file_id]
        
        # Create encrypted package containing encrypted data and wrapped key
        encrypted_package = {
            'filename': file_info['filename'],
            'encrypted_data': {
                'ciphertext': base64.b64encode(file_info['encrypted_data']['ciphertext']).decode('utf-8'),
                'iv': base64.b64encode(file_info['encrypted_data']['iv']).decode('utf-8'),
                'auth_tag': base64.b64encode(file_info['encrypted_data']['auth_tag']).decode('utf-8')
            },
            'wrapped_key': base64.b64encode(file_info['wrapped_key']).decode('utf-8'),
            'algorithm': 'AES-256-GCM',
            'key_wrap_algorithm': 'RSA-OAEP-SHA256',
            'upload_time': file_info['upload_time']
        }
        
        # Convert to JSON and create download
        package_json = json.dumps(encrypted_package, indent=2)
        encrypted_filename = f"{file_info['filename']}.encrypted"
        
        # Return encrypted package as download
        return send_file(
            io.BytesIO(package_json.encode('utf-8')),
            as_attachment=True,
            download_name=encrypted_filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        logger.error(f"Download failed: {e}")
        return jsonify({'error': sanitize_error(e)}), 500

@app.route('/api/files')
@require_auth
def list_files():
    """List all stored encrypted files"""
    files = []
    for file_id, info in file_storage.items():
        files.append({
            'file_id': file_id,
            'filename': info['filename'],
            'upload_time': info['upload_time']
        })
    return jsonify({'files': files})


@app.route('/api/hsm-status')
@require_auth
def hsm_status():
    """Get HSM status information (limited details for security)"""
    key_info = hsm.get_key_info()
    return jsonify({
        'status': 'active',
        'key_size': key_info['key_size'],
        'fingerprint': key_info['fingerprint'],
        'algorithm': key_info['algorithm']
    })

@app.route('/api/generate-keypair', methods=['POST'])
@require_auth
def generate_new_keypair():
    """Generate a new RSA keypair"""
    try:
        hsm.generate_rsa_keypair()
        key_info = hsm.get_key_info()
        return jsonify({
            'success': True,
            'message': 'New RSA keypair generated successfully',
            'key_info': key_info
        })
    except Exception as e:
        logger.error(f"Keypair generation failed: {e}")
        return jsonify({'error': sanitize_error(e)}), 500

@app.route('/api/public-key')
@require_auth
def get_public_key():
    """Get the current public key in PEM format"""
    try:
        public_key_pem = hsm.get_public_key_pem()
        key_info = hsm.get_key_info()
        return jsonify({
            'public_key_pem': public_key_pem,
            'key_info': key_info
        })
    except Exception as e:
        logger.error(f"Public key export failed: {e}")
        return jsonify({'error': sanitize_error(e)}), 500

@app.route('/api/private-key')
@require_auth
def get_private_key():
    """Get the current private key in PEM format (SECURITY SENSITIVE)"""
    try:
        private_key_pem = hsm.get_private_key_pem()
        key_info = hsm.get_key_info()
        
        # Log this sensitive operation
        logger.warning(f"Private key accessed by user: {session.get('username', 'unknown')}")
        
        return jsonify({
            'private_key_pem': private_key_pem,
            'key_info': key_info
        })
    except Exception as e:
        logger.error(f"Private key export failed: {e}")
        return jsonify({'error': sanitize_error(e)}), 500

if __name__ == '__main__':
    # Security: Disable debug mode in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)