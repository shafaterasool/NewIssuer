import os
import json
import hashlib
from eth_account import Account
from web3 import Web3
from dotenv import load_dotenv
from config import RPC_URL, CONTRACT_ADDRESS, CONTRACT_ABI, CHAIN_ID 

# --- Initialization ---
load_dotenv()
w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected()

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

issuer_key = os.getenv("NADRA_PRIVATE_KEY")
assert issuer_key

def create_cnic_credential(citizen_address, full_name, father_name, resident_address, city, dob):
    """Creates a standardized verifiable credential for a citizen."""
    return {
        "issuer": "National Database and Registration Authority",
        "credentialType": "NationalIdentityCredential",
        "fullName": full_name,
        "fatherName": father_name,
        "residentAddress": resident_address,
        "city": city,
        "dateOfBirth": dob,
        
    }

def hash_data(data):
    
    json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(json_str.encode()).hexdigest()

def issue_cnic_credential(citizen_address, metadata):
    try:
        citizen_address = Web3.to_checksum_address(citizen_address)
        credential_hash = hash_data(metadata)
        bytes_hash = bytes.fromhex(credential_hash)
        issuer_account = Account.from_key(issuer_key)
        
        print(f"\nIssuing credential for {citizen_address} from NADRA address {issuer_account.address}...")
        
        tx = contract.functions.issueCredential(
            citizen_address,
            bytes_hash
        ).build_transaction({
            'chainId': CHAIN_ID,
            'gas': 300000,
            'maxFeePerGas': w3.to_wei('40', 'gwei'),
            'maxPriorityFeePerGas': w3.to_wei('2', 'gwei'),
            'nonce': w3.eth.get_transaction_count(issuer_account.address),
        })
        
        signed_tx = issuer_account.sign_transaction(tx)
        
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        print("\n✅ National Identity Credential Issued Successfully!")
        print(f"Transaction Hash: {tx_hash.hex()}")
        print(f"Block Number: {receipt['blockNumber']}")
        print(f"Citizen's Address: {citizen_address}")
        print(f"Stored Credential Hash: {credential_hash}")
        return receipt
        
    except Exception as e:
        print(f"\n❌ Transaction Failed: {e}")
        raise

if __name__ == "__main__":
    print("=====================================================")
    print("=== Verifiable Credential Issuance System ===")
    print("=====================================================")
    try:
        address = input("Enter the Citizen wallet address (0x...): ").strip()
        name = input("Enter the Citizen Full Name: ").strip()
        father_name = input("Enter the Citizen's Father Name: ").strip()
        resident_address = input("Enter the Resident Address: ").strip()
        city = input("Enter the City: ").strip()
        date_of_birth = input("Enter the Citizen Date of Birth (YYYY-MM-DD): ").strip()
        
        metadata = create_cnic_credential(
            address, 
            name, 
            father_name, 
            resident_address, 
            city, 
            date_of_birth
        )
        
        print("\n--- Credential Data to be Hashed ---")
        print(json.dumps(metadata, indent=2))
        print("-------------------------------------")
        
        # Issue the credential on the blockchain
        issue_cnic_credential(address, metadata)
        
    except Exception as e:
        print(f"\n❌ Error during issuance: {e}")