# Fingerprint Data Storage on Solana Blockchain

This project provides functionality to securely encrypt fingerprint images and store them on the Solana blockchain, along with retrieval capabilities.

## Key Features

- Fingerprint image processing and encryption
- Encrypted data storage on Solana blockchain
- Data retrieval and decryption from blockchain

## Getting Started

### Prerequisites

- Python 3.7 or higher
- OpenCV (`cv2`)
- Solana packages (`solders`, `solana`)
- Other dependencies: `cryptography`, `Pillow`, `numpy`, `aiohttp`

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd testinghandpring
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

### Configuration

1. Visit iq6900.com, connect your wallet and register.

This is a PDA generation procedure that is currently set up this way for security reasons. Once Code-in is updated, we will provide a simpler procedure.

2. Create a `.env` file in the root directory:
```bash
cp .env.example .env
```

3. Edit the `.env` file with your credentials:
```
SOLANA_NETWORK="your-rpc-endpoint-here"
WALLET_SECRET_KEY="your-base58-encoded-secret-key-here"
```

**IMPORTANT: Never commit your `.env` file to version control. It is already added to `.gitignore`.**

## Usage

1. Prepare your fingerprint image.

2. Run the program:
```python
python finger.py <image_path>
```

### Process Flow

1. **Image Processing and Encryption**
   - Load and preprocess the image
   - Encrypt the data

2. **Blockchain Storage**
   - Store encrypted data on Solana blockchain
   - Wait for transaction confirmation (about 30 seconds)

3. **Data Retrieval**
   - Search recent transactions through DBPDA
   - Decrypt the encrypted data

## Important Notes

- Never include sensitive keys directly in the code
- Always use environment variables for sensitive data
- Proper environment variable management is required in production
- Transaction confirmation time may vary depending on network conditions
- Do not share your wallet secret key with anyone

## License

This project is distributed under [License Name].
