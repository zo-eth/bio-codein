import asyncio
from cryptography.fernet import Fernet
import cv2
import numpy as np
from PIL import Image
import hashlib
import base64
import json
import aiohttp
from typing import List
from codein_handler import (
    on_chain_text_in, 
    get_dbpda, 
    get_transaction_result, 
    get_transaction_info,
    UserKeyString, 
    NETWORK
)

def process_fingerprint_image(image_path):
    # 이미지 읽기
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError(f"Failed to load image from {image_path}")
    
    # 이미지 전처리
    img = cv2.equalizeHist(img)
    img = cv2.GaussianBlur(img, (5,5), 0)
    
    # 지문 특징점 추출
    sift = cv2.SIFT_create()
    keypoints, descriptors = sift.detectAndCompute(img, None)
    
    if descriptors is None:
        raise ValueError("No fingerprint features detected")
    
    return descriptors

def generate_key_from_fingerprint(descriptors):
    # 특징점 데이터를 바이트로 변환
    feature_bytes = descriptors.tobytes()
    
    # SHA-256 해시 생성
    hash_object = hashlib.sha256(feature_bytes)
    hash_bytes = hash_object.digest()
    
    # Fernet 키 생성을 위한 base64 인코딩
    key = base64.urlsafe_b64encode(hash_bytes)
    return key

def encrypt_data(data: str, fingerprint_image_path: str) -> bytes:
    """
    지문 이미지를 사용하여 데이터를 암호화합니다.
    """
    # 지문 처리
    descriptors = process_fingerprint_image(fingerprint_image_path)
    key = generate_key_from_fingerprint(descriptors)
    
    # 암호화
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data: bytes, fingerprint_image_path: str) -> str:
    """
    지문 이미지를 사용하여 암호화된 데이터를 복호화합니다.
    """
    # 지문 처리
    descriptors = process_fingerprint_image(fingerprint_image_path)
    key = generate_key_from_fingerprint(descriptors)
    
    # 복호화
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode()

async def store_encrypted_data_onchain(encrypted_data: bytes, handle: str) -> str:
    """
    암호화된 데이터를 블록체인에 저장합니다.
    """
    # bytes를 문자열로 변환
    encrypted_str = encrypted_data.hex()
    
    # 블록체인에 데이터 저장
    result = await on_chain_text_in(encrypted_str, handle)
    return result

async def get_dbpda_transactions(dbpda: str) -> List[str]:
    """
    DBPDA 계정의 트랜잭션 목록을 가져옵니다.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                NETWORK,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getSignaturesForAddress",
                    "params": [
                        dbpda,
                        {"limit": 30}  # 최근 30개만 가져오기
                    ]
                }
            ) as response:
                result = await response.json()
                if 'result' in result:
                    return [tx['signature'] for tx in result['result']]
                return []
    except Exception as e:
        print(f"Error getting DBPDA transactions: {e}")
        return []

async def get_encrypted_data_from_chain(user_key: str) -> bytes:
    """
    사용자의 dbpda를 확인하고 블록체인에서 암호화된 데이터를 검색합니다.
    최근 30개의 트랜잭션만 확인합니다.
    """
    # 사용자의 dbpda 가져오기
    dbpda = await get_dbpda(user_key)
    print(f"DBPDA: {dbpda}")
    
    # DBPDA의 트랜잭션 목록 가져오기
    tx_signatures = await get_dbpda_transactions(dbpda)
    print(f"Found {len(tx_signatures)} transactions")
    
    # 각 트랜잭션을 확인
    for i, signature in enumerate(tx_signatures):
        print(f"\nChecking transaction {i+1}/{len(tx_signatures)}: {signature}")
        
        # 트랜잭션 타입 확인
        tx_info = await get_transaction_info(signature)
        if not tx_info:
            print(f"No info for transaction {signature}")
            continue
            
        # fingerHashedData 타입인지 확인
        if 'fingerHashedData' in tx_info:
            print(f"Found fingerHashedData type in transaction {i+1}")
            
            # 트랜잭션 결과 가져오기
            tx_result = await get_transaction_result(signature)
            if not tx_result:
                print(f"No result for transaction {signature}")
                continue
                
            print(f"Found encrypted data, returning for decryption")
            return bytes.fromhex(tx_result)
    
    raise ValueError("No fingerprint data found in last 30 transactions")

async def main():
    try:
        # test data 
        fingerprint_image = "images/finger.jpeg"  # 지문 이미지 경로
        secret_message = "This is a secret message that will be encrypted with the fingerprint!"
        handle = "python"  # 블록체인 핸들
        
        print("🔹 Original Message:", secret_message)
        
        # 1. encrypt
        print("\n1️⃣ Encrypting data with fingerprint...")
        encrypted_data = encrypt_data(secret_message, fingerprint_image)
        print("✅ Data encrypted successfully!")
        
        # 2. store on blockchain
        print("\n2️⃣ Storing encrypted data on blockchain...")
        result = await store_encrypted_data_onchain(encrypted_data, handle)
        print("✅ Data stored on blockchain:", result)
        
        # 블록체인에 데이터가 기록될 때까지 대기
        print("\n⏳ Waiting for blockchain confirmation (30 seconds)...")
        await asyncio.sleep(30)
        
        # 3. retrieve and decrypt
        print("\n3️⃣ Retrieving and decrypting data...")
        try:
            # UserKeyString을 사용하여 블록체인에서 암호화된 데이터 가져오기
            retrieved_encrypted_data = await get_encrypted_data_from_chain(UserKeyString)
            
            # 복호화
            decrypted_message = decrypt_data(retrieved_encrypted_data, fingerprint_image)
            print("✅ Decrypted Message:", decrypted_message)
            
            if secret_message == decrypted_message:
                print("\n🎉 Success! The message was successfully encrypted, stored, retrieved and decrypted!")
            else:
                print("\n❌ Warning: Decrypted message doesn't match the original!")
        except Exception as e:
            print(f"\n❌ Error during decryption: {e}")
            
    except Exception as e:
        print(f"\n❌ Error in main: {e}")

if __name__ == "__main__":
    asyncio.run(main())