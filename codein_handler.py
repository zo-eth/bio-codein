from solana.rpc.api import Client
from solders.transaction import Transaction, VersionedTransaction
from solders.keypair import Keypair
from solders.pubkey import Pubkey as PublicKey
from solders.instruction import Instruction, AccountMeta
from solders.system_program import ID as SYS_PROGRAM_ID
from solders.message import Message
from solders.hash import Hash
from solana.rpc.async_api import AsyncClient
from solana.transaction import Transaction as LegacyTransaction
import base64
import aiohttp
import asyncio
import json
import base58
import os
from dotenv import load_dotenv

from typing import List, Optional

# Load environment variables
load_dotenv()

# Constants
IQ_HOST = "https://solanacontractapi.uc.r.appspot.com"
NETWORK = os.getenv("SOLANA_NETWORK")  # Load from environment variable
PROGRAM_ID = PublicKey.from_string("FG5nDUjz4S1FBs2rZrXsKsa7J34e21WF17F8nFL9uwWi")

# Configuration
SECRET_KEY_BASE58 = os.getenv("WALLET_SECRET_KEY")  # Load from environment variable
if not SECRET_KEY_BASE58:
    raise ValueError("WALLET_SECRET_KEY environment variable is not set")
if not NETWORK:
    raise ValueError("SOLANA_NETWORK environment variable is not set")

TRANSACTION_SIZE_LIMIT = 850
SIZE_LIMIT_FOR_SPLIT_COMPRESSION = 10000
UserKey = Keypair.from_base58_string(SECRET_KEY_BASE58)
UserKeyString = str(UserKey.pubkey())

def create_transaction_from_json(tx_json: dict) -> LegacyTransaction:
    # Create instruction
    instruction_data = tx_json['instructions'][0]
    
    # Convert account keys
    keys = []
    for key in instruction_data['keys']:
        keys.append(
            AccountMeta(
                pubkey=PublicKey.from_string(key['pubkey']),
                is_signer=key['isSigner'],
                is_writable=key['isWritable']
            )
        )
    
    # Create instruction
    instruction = Instruction(
        program_id=PublicKey.from_string(instruction_data['programId']),
        accounts=keys,
        data=bytes(instruction_data['data'])
    )
    
    # Create legacy transaction
    tx = LegacyTransaction()
    tx.add(instruction)
    tx.fee_payer = PublicKey.from_string(tx_json['feePayer'])
    
    return tx

async def get_transaction_result(tail_tx: str) -> Optional[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{IQ_HOST}/get_transaction_result/{tail_tx}") as response:
                return await response.text()
    except Exception as e:
        print(f"Error getting transaction result: {e}")
        return None

async def get_pda( user_key: str) -> Optional[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{IQ_HOST}/getPDA/{user_key}") as response:
                if response.status == 200:
                    data = await response.json()
                    return data['PDA']
                return None
    except Exception as e:
        print(f"Error getting PDA: {e}")
        return None

async def get_dbpda(user_key: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{IQ_HOST}/getDBPDA/{user_key}") as response:
                if response.status == 200:
                    data = await response.json()
                    return data['DBPDA']
                return "null"
    except Exception as e:
        print(f"Error getting DBPDA: {e}")
        return "null"

async def create_send_transaction_on_server(code, before_tx, method, decode_break):
    url = f"{IQ_HOST}/create-send-transaction"

    request_data = {
        'userKeyString': UserKeyString,
        'code': code,
        'before_tx': before_tx,
        'method': method,
        'decode_break': decode_break,
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=request_data) as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, dict) and 'transaction' in data:
                        return create_transaction_from_json(data['transaction'])
                    raise Exception(f"Invalid transaction data format: {data}")
                response.raise_for_status()
    except Exception as e:
        print(f"Failed to create transaction: {e}")
        raise

async def create_db_code_transaction_on_server(handle, tail_tx, type_, offset):
    url = f"{IQ_HOST}/create-db-code-free-transaction"

    request_data = {
        'userKeyString': UserKeyString,
        'handle': handle,
        'tail_tx': tail_tx,
        'type': type_,
        'offset': offset
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=request_data) as response:
                if response.status == 200:
                    data = await response.json()
                    if isinstance(data, dict) and 'transaction' in data:
                        return create_transaction_from_json(data['transaction'])
                    raise Exception(f"Invalid transaction data format: {data}")
                response.raise_for_status()
    except Exception as e:
        print(f"Failed to create transaction: {e}")
        raise

async def tx_send(tx: LegacyTransaction) -> str:
    try:
        client = AsyncClient(NETWORK)
        # Get latest blockhash
        blockhash = await client.get_latest_blockhash()
        if not blockhash:
            return "null"

        # Update transaction
        tx.recent_blockhash = blockhash.value.blockhash
        tx.sign(UserKey)

        # Convert transaction to bytes and send
        tx_bytes = tx.serialize()
        tx_base64 = base64.b64encode(tx_bytes).decode('utf-8')
        
        # Send transaction using RPC request
        async with aiohttp.ClientSession() as session:
            async with session.post(
                NETWORK,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "sendTransaction",
                    "params": [
                        tx_base64,
                        {"encoding": "base64", "preflightCommitment": "confirmed"}
                    ]
                }
            ) as response:
                result = await response.json()
                if 'result' in result:
                    print(f'txid: {result["result"]}')
                    return result['result']
                elif 'error' in result:
                    print('Error:', result['error'])
                return "null"

    except Exception as e:
        print(f"Error sending transaction: {e}")
        return "null"

async def get_chunk( text_data: str, chunk_size: int) -> List[str]:
    data_length = len(text_data)
    total_chunks = (data_length + chunk_size - 1) // chunk_size
    chunks = [text_data[i * chunk_size: (i + 1) * chunk_size] for i in range(total_chunks)]
    return chunks



async def on_chain_text_in( data: str, handle: str):
    chunk_list = await get_chunk(data, TRANSACTION_SIZE_LIMIT)
    merkle_root = await make_merkle_root_from_server(chunk_list)
    print(merkle_root)
    print("Chunk size:", len(chunk_list) + 1)
    result = await make_text_transactions(chunk_list, handle, "fingerHashedData", merkle_root)
    return result

async def make_merkle_root_from_server(data_list):
    url = f"{IQ_HOST}/generate-merkle-root"
    request_data = {
        "data": data_list,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=request_data, headers={"Content-Type": "application/json"}) as response:
                if response.status == 200:
                    response_data = await response.json()
                    return response_data.get('merkleRoot')
                else:
                    raise Exception(response.status)
    except Exception as error:
        print("Failed to get Merkle Root:", error)
        raise error

async def make_text_transactions( chunk_list, handle, type_, offset):
    before_hash = "Genesis"
    method = 0
    decode_break = 0
    for text in chunk_list:
        tx = await create_send_transaction_on_server(text, before_hash, method, decode_break)
        before_hash = await tx_send(tx)

    tx = await create_db_code_transaction_on_server(handle, before_hash, type_, offset)
    return await tx_send(tx)

async def get_transaction_info(tx_id: str) -> Optional[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{IQ_HOST}/get_transaction_info/{tx_id}") as response:
                return await response.text()
    except Exception as e:
        print(f"Error getting transaction info: {e}")
        return None

# Example usage
async def main():
    try:
        # Example: On-chain text in
        result = await on_chain_text_in("hello", "python")
        print("On-chain text in result:", result)
        
    except Exception as e:
        print(f"Error in main: {e}")

if __name__ == "__main__":
    asyncio.run(main())