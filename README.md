# Secure Data Storage and Retrieval System

A Streamlit-based application for secure data storage and retrieval with encryption capabilities.

## Features

- Secure data storage with unique passkeys
- Data encryption using Fernet (from cryptography library)
- Passkey hashing using SHA-256
- Three-attempt limit for data retrieval
- Simple login system
- In-memory data storage
- User-friendly interface

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
streamlit run app.py
```

2. Login to the system:
   - Default login password: `admin123`

3. Choose between storing or retrieving data:
   - Store Data: Enter a passkey and the data you want to store
   - Retrieve Data: Enter the passkey to retrieve the stored data

## Security Features

- All passkeys are hashed using SHA-256
- Data is encrypted using Fernet encryption
- Three failed attempts will force reauthorization
- All data is stored in memory (no persistent storage)

## Note

This is a demonstration system. For production use, consider implementing:
- More secure authentication
- Persistent storage
- Additional security measures
- Proper error handling
- Logging system 