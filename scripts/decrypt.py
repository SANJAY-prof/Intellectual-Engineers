#!/usr/bin/env python3
"""
HSM File Decryption Tool

This script decrypts files that were encrypted by the RSA + HSM system.
It uses the private key to unwrap the AES key and then decrypts the file data.

Usage:
    python decrypt.py --package <encrypted_file.encrypted> --private-key <private.pem> [--output <decrypted_file>]

Example:
    python decrypt.py --package document.pdf.encrypted --private-key private_key.pem --output document.pdf
"""

import argparse
import json
import base64
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: cryptography library is required. Install with: pip install cryptography")
    sys.exit(1)


def load_encrypted_package(package_path):
    """Load and parse the encrypted package JSON file"""
    try:
        with open(package_path, 'r') as f:
            package = json.load(f)
        
        # Validate required fields
        required_fields = ['filename', 'encrypted_data', 'wrapped_key', 'algorithm', 'key_wrap_algorithm']
        for field in required_fields:
            if field not in package:
                raise ValueError(f"Missing required field: {field}")
        
        # Decode base64 data
        encrypted_data = {
            'ciphertext': base64.b64decode(package['encrypted_data']['ciphertext']),
            'iv': base64.b64decode(package['encrypted_data']['iv']),
            'auth_tag': base64.b64decode(package['encrypted_data']['auth_tag'])
        }
        wrapped_key = base64.b64decode(package['wrapped_key'])
        
        return package['filename'], encrypted_data, wrapped_key, package
        
    except FileNotFoundError:
        print(f"Error: Package file '{package_path}' not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in package file '{package_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading package: {e}")
        sys.exit(1)


def load_private_key(key_path):
    """Load the RSA private key from PEM file"""
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        private_key = serialization.load_pem_private_key(
            key_data,
            password=None,  # Assuming unencrypted key
            backend=default_backend()
        )
        
        return private_key
        
    except FileNotFoundError:
        print(f"Error: Private key file '{key_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading private key: {e}")
        sys.exit(1)


def unwrap_aes_key(private_key, wrapped_key):
    """Unwrap the AES key using RSA-OAEP"""
    try:
        aes_key = private_key.decrypt(
            wrapped_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        if len(aes_key) != 32:  # 256 bits
            raise ValueError(f"Unexpected AES key length: {len(aes_key)} bytes (expected 32)")
        
        return aes_key
        
    except Exception as e:
        print(f"Error unwrapping AES key: {e}")
        print("This usually means the private key doesn't match the encrypted file")
        sys.exit(1)


def decrypt_file_data(encrypted_data, aes_key):
    """Decrypt the file data using AES-256-GCM"""
    try:
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(encrypted_data['iv'], encrypted_data['auth_tag']),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        return plaintext
        
    except Exception as e:
        print(f"Error decrypting file data: {e}")
        print("This could indicate file corruption or wrong decryption key")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt files encrypted by the RSA + HSM system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --package document.pdf.encrypted --private-key private.pem
  %(prog)s --package secret.txt.encrypted --private-key private.pem --output decrypted_secret.txt
        """
    )
    
    parser.add_argument('--package', '-p', required=True,
                       help='Path to the encrypted package file (.encrypted)')
    parser.add_argument('--private-key', '-k', required=True,
                       help='Path to the RSA private key file (.pem)')
    parser.add_argument('--output', '-o',
                       help='Output file path (default: original filename)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed information during decryption')
    
    args = parser.parse_args()
    
    if args.verbose:
        print("=== HSM File Decryption Tool ===")
        print(f"Package file: {args.package}")
        print(f"Private key: {args.private_key}")
    
    # Load encrypted package
    if args.verbose:
        print("\n1. Loading encrypted package...")
    filename, encrypted_data, wrapped_key, package = load_encrypted_package(args.package)
    
    if args.verbose:
        print(f"   Original filename: {filename}")
        print(f"   Algorithm: {package.get('algorithm', 'Unknown')}")
        print(f"   Key wrap algorithm: {package.get('key_wrap_algorithm', 'Unknown')}")
        print(f"   Ciphertext size: {len(encrypted_data['ciphertext'])} bytes")
    
    # Load private key
    if args.verbose:
        print("\n2. Loading RSA private key...")
    private_key = load_private_key(args.private_key)
    
    if args.verbose:
        print(f"   Key size: {private_key.key_size} bits")
    
    # Unwrap AES key
    if args.verbose:
        print("\n3. Unwrapping AES key...")
    aes_key = unwrap_aes_key(private_key, wrapped_key)
    
    if args.verbose:
        print(f"   AES key length: {len(aes_key)} bytes")
    
    # Decrypt file data
    if args.verbose:
        print("\n4. Decrypting file data...")
    plaintext = decrypt_file_data(encrypted_data, aes_key)
    
    if args.verbose:
        print(f"   Decrypted size: {len(plaintext)} bytes")
    
    # Determine output file
    if args.output:
        output_path = args.output
    else:
        # Remove .encrypted extension if present
        output_path = filename
        if args.package.endswith('.encrypted'):
            base_name = Path(args.package).stem
            if base_name.endswith('.encrypted'):
                base_name = base_name[:-10]  # Remove .encrypted
            output_path = base_name or filename
    
    # Write decrypted file
    if args.verbose:
        print(f"\n5. Writing decrypted file: {output_path}")
    
    try:
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"✅ Successfully decrypted to: {output_path}")
        
        if args.verbose:
            print(f"\nDecryption completed successfully!")
            print(f"Input:  {args.package}")
            print(f"Output: {output_path}")
            print(f"Size:   {len(plaintext):,} bytes")
    
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)
    
    finally:
        # Clear sensitive data
        if 'aes_key' in locals():
            aes_key = b'\x00' * len(aes_key)


if __name__ == '__main__':
    main()