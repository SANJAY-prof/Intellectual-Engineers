# Defense System File Encryption - RSA + HSM

## Overview

This is a Flask-based web application that simulates a Hardware Security Module (HSM) for secure file encryption and decryption in defense systems. The application provides a secure file encryption service using hybrid cryptography (AES-256-GCM for file encryption and RSA-OAEP for key wrapping) with HSM simulation for key management operations. It features a web interface for file upload, encryption, storage, and retrieval with comprehensive operation logging for audit trails.

**Current Status**: Fully functional prototype with authentication, secure encryption, and manual decryption workflow. Features key generation, public/private key export, and encrypted file downloads requiring external decryption with private key.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Web Framework
- **Flask Application**: Simple Python web framework serving both API endpoints and web interface
- **Session Management**: Flask sessions with configurable secret key for user authentication
- **Template Rendering**: Jinja2 templates with Bootstrap frontend for user interface

### Security Architecture
- **Authentication**: Simple username/password authentication with session-based access control
- **HSM Simulation**: Custom HSMSimulator class that mimics hardware security module operations
- **Hybrid Cryptography**: 
  - AES-256-GCM for symmetric file encryption (fast for large files)
  - RSA-2048 with OAEP padding for asymmetric key wrapping (secure key exchange)
  - Cryptography library for all cryptographic operations

### Data Storage
- **In-Memory Storage**: File storage and operation logs stored in Python dictionaries
- **No Persistent Database**: All data is volatile and lost on application restart
- **Base64 Encoding**: Encrypted data encoded for safe transmission and storage

### Key Management
- **RSA Keypair Generation**: 2048-bit RSA keys generated on HSM simulator initialization
- **Key Wrapping**: AES encryption keys are wrapped using RSA public key encryption
- **Secure Key Derivation**: Random AES keys generated using cryptographically secure methods

### Logging and Auditing
- **Operation Logging**: All cryptographic operations logged with timestamps
- **Structured Logging**: Python logging module for application-level logging
- **Audit Trail**: Complete history of encryption/decryption operations maintained

## External Dependencies

### Python Cryptography Libraries
- **cryptography**: Primary cryptographic library for all encryption operations
- **secrets**: Secure random number generation for keys and tokens

### Web Framework Dependencies
- **Flask**: Core web framework for HTTP handling and routing
- **Jinja2**: Template engine (included with Flask)

### Frontend Dependencies
- **Bootstrap 5.1.3**: CSS framework for responsive UI design
- **Font Awesome 6.0.0**: Icon library for enhanced user interface

### Environment Configuration
- **SESSION_SECRET**: Configurable session secret key via environment variable
- **APP_USERNAME/APP_PASSWORD**: Configurable authentication credentials

### No External Services
- Application is self-contained with no external API dependencies
- No database connections or cloud service integrations
- Designed for isolated, secure environments typical in defense systems