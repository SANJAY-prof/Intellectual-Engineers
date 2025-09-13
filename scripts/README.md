# HSM File Decryption Guide

This guide shows you how to decrypt files that were encrypted by the RSA + HSM system using your private key.

## Quick Start

1. **Download encrypted file** from the HSM system (ends with `.encrypted`)
2. **Export private key** using "View Private Key" button, save as `private.pem`
3. **Run decryption script**:
   ```bash
   python scripts/decrypt.py --package yourfile.pdf.encrypted --private-key private.pem
   ```

## Step-by-Step Instructions

### 1. Get Your Files
- **Encrypted file**: Download from HSM system (e.g., `document.pdf.encrypted`)
- **Private key**: Click "View Private Key" → Copy → Save as `private.pem`

### 2. Install Requirements
```bash
pip install cryptography
```

### 3. Decrypt Files

**Basic usage:**
```bash
python scripts/decrypt.py --package document.pdf.encrypted --private-key private.pem
```

**Specify output filename:**
```bash
python scripts/decrypt.py --package secret.txt.encrypted --private-key private.pem --output decrypted_secret.txt
```

**Verbose output:**
```bash
python scripts/decrypt.py --package document.pdf.encrypted --private-key private.pem --verbose
```

## File Format

The encrypted files contain:
- **Original filename**
- **AES-256-GCM encrypted data** (ciphertext + IV + authentication tag)
- **RSA-wrapped AES key** (encrypted with your public key)
- **Algorithm details** (AES-256-GCM + RSA-OAEP-SHA256)

## Security Notes

⚠️ **Keep your private key secure!**
- Never share your private key
- Store it in a secure location
- Clear it from clipboard after use
- The private key can decrypt ALL your encrypted files

## Troubleshooting

**"Error unwrapping AES key"**
- Wrong private key for this encrypted file
- Make sure you're using the private key from the same HSM session

**"cryptography library is required"**
- Install with: `pip install cryptography`

**"File not found"**
- Check file paths are correct
- Make sure both encrypted file and private key exist

**"Invalid JSON in package file"**
- Encrypted file may be corrupted
- Re-download from HSM system

## Advanced Usage (OpenSSL)

For advanced users, you can also decrypt using OpenSSL commands:

1. **Extract components from JSON:**
   ```bash
   # Parse the .encrypted file and extract base64 fields
   cat yourfile.pdf.encrypted | jq -r '.wrapped_key' | base64 -d > wrapped_key.bin
   cat yourfile.pdf.encrypted | jq -r '.encrypted_data.ciphertext' | base64 -d > ciphertext.bin
   cat yourfile.pdf.encrypted | jq -r '.encrypted_data.iv' | base64 -d | xxd -p -c 256 > iv.hex
   cat yourfile.pdf.encrypted | jq -r '.encrypted_data.auth_tag' | base64 -d | xxd -p -c 256 > tag.hex
   ```

2. **Unwrap AES key:**
   ```bash
   openssl pkeyutl -decrypt -inkey private.pem \
     -pkeyopt rsa_padding_mode:oaep \
     -pkeyopt rsa_oaep_md:sha256 \
     -pkeyopt rsa_mgf1_md:sha256 \
     -in wrapped_key.bin -out aes.key
   ```

3. **Decrypt file:**
   ```bash
   openssl enc -d -aes-256-gcm \
     -K $(xxd -p -c 256 aes.key) \
     -iv $(cat iv.hex) \
     -in ciphertext.bin \
     -out yourfile.pdf \
     -tag $(cat tag.hex)
   ```

**Requirements:** OpenSSL 1.1.1+ (for GCM support)