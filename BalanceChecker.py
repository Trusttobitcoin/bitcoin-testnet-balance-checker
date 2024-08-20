import os
import hashlib
import hmac
import ecdsa
import base58
import base64
from ripemd160 import ripemd160
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bech32
import requests
import logging
import asyncio
import aiohttp
import ssl
import json
import random
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
class ElectrumClient:
    def __init__(self):
        self.socket = None
        self.server_info = None

    async def connect(self):
        servers = [
            ("testnet.aranguren.org", 51002, True),   # SSL
            ("testnet.aranguren.org", 51001, False),  # Non-SSL
        ]

        for host, port, use_ssl in servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)  # Set a 10-second timeout
                logger.info(f"Attempting to connect to {host}:{port} ({'SSL' if use_ssl else 'Non-SSL'})")

                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)

                sock.connect((host, port))
                logger.info("Connected successfully")

                # Test the connection with a server.version request
                message = json.dumps({"id": 1, "method": "server.version", "params": []}) + "\n"
                sock.sendall(message.encode())
                logger.info("Sent server.version request")

                response = sock.recv(1024).decode()
                logger.info(f"Received response: {response}")

                self.socket = sock
                self.server_info = (host, port, use_ssl)
                logger.info(f"Successfully connected to {host}:{port} ({'SSL' if use_ssl else 'Non-SSL'})")
                return
            except Exception as e:
                logger.error(f"Connection failed to {host}:{port}: {str(e)}")
                if sock:
                    sock.close()

        raise Exception("Failed to connect to any Electrum server")

    async def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None
            self.server_info = None

    async def request(self, method, params):
        if not self.socket:
            await self.connect()

        message = json.dumps({"id": 1, "method": method, "params": params}) + "\n"
        self.socket.sendall(message.encode())
        
        response = b""
        while b"\n" not in response:
            chunk = self.socket.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed by server")
            response += chunk

        response = json.loads(response.decode())
        if "error" in response:
            raise Exception(f"RPC error: {response['error']}")
        return response["result"]

    async def get_balance(self, address):
        script_hash = self.address_to_scripthash(address)
        balance = await self.request("blockchain.scripthash.get_balance", [script_hash])
        return balance

    def address_to_scripthash(self, address):
        script = self.address_to_script(address)
        return hashlib.sha256(bytes.fromhex(script)).digest()[::-1].hex()

    def address_to_script(self, address):
        if address.startswith('m') or address.startswith('n'):  # P2PKH
            pubkey_hash = self.address_to_pubkey_hash(address)
            return f"76a914{pubkey_hash}88ac"
        elif address.startswith('2'):  # P2SH
            script_hash = self.address_to_pubkey_hash(address)
            return f"a914{script_hash}87"
        elif address.startswith('tb1'):  # Bech32
            witver, witprog = bech32.decode('tb', address)
            if witver == 0 and len(witprog) == 20:  # P2WPKH
                return f"0014{bytes(witprog).hex()}"
            elif witver == 0 and len(witprog) == 32:  # P2WSH
                return f"0020{bytes(witprog).hex()}"
        raise ValueError(f"Unsupported address format: {address}")

    def address_to_pubkey_hash(self, address):
        if address.startswith('m') or address.startswith('n') or address.startswith('2'):
            return base58.b58decode_check(address)[1:].hex()
        elif address.startswith('tb1'):
            _, data = bech32.decode('tb', address)
            return ''.join([f'{x:02x}' for x in data])
        else:
            raise ValueError("Unsupported address format")
class BitcoinTestnetHDWallet:
    def __init__(self, wallet_file='wallet.enc'):
        self.wallet_file = wallet_file
        self.mnemonic = None
        self.seed = None
        self.master_key = None
        self.addresses = []
        self.electrum_client = None

    def load_existing_wallet(self, password):
        if not os.path.exists(self.wallet_file):
            raise FileNotFoundError("Wallet file not found.")
        self.mnemonic = self.load_wallet(password)
        self.seed = self.mnemonic_to_seed(self.mnemonic)
        self.master_key = self.generate_master_key()

    def mnemonic_to_seed(self, mnemonic, passphrase=""):
        mnemonic = mnemonic.encode('utf-8')
        salt = ("mnemonic" + passphrase).encode('utf-8')
        return hashlib.pbkdf2_hmac("sha512", mnemonic, salt, 2048, 64)

    def generate_master_key(self):
        key = hmac.new(b"Bitcoin seed", self.seed, hashlib.sha512).digest()
        return {'private_key': key[:32], 'chain_code': key[32:]}

    def derive_child_key(self, parent_key, index):
        if index >= 0x80000000:
            data = b'\x00' + parent_key['private_key'] + index.to_bytes(4, 'big')
        else:
            parent_public_key = self.private_to_public(parent_key['private_key'])
            data = parent_public_key + index.to_bytes(4, 'big')

        key = hmac.new(parent_key['chain_code'], data, hashlib.sha512).digest()
        child_private_key = (int.from_bytes(key[:32], 'big') + int.from_bytes(parent_key['private_key'], 'big')) % ecdsa.SECP256k1.order
        child_chain_code = key[32:]

        return {'private_key': child_private_key.to_bytes(32, 'big'), 'chain_code': child_chain_code}

    def derive_path(self, path):
        key = self.master_key
        for index in path:
            key = self.derive_child_key(key, index)
        return key

    def private_to_public(self, private_key):
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        return b'\x02' + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]

    def public_key_to_p2pkh_address(self, public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = ripemd160(sha256_hash)
        version_payload = b'\x6f' + ripemd160_hash  # 0x6f is the version byte for testnet
        checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
        binary_address = version_payload + checksum
        return base58.b58encode(binary_address).decode('utf-8')

    def public_key_to_p2sh_address(self, public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = ripemd160(sha256_hash)
        redeemScript = b'\x00\x14' + ripemd160_hash
        scriptHash = ripemd160(hashlib.sha256(redeemScript).digest())
        version_payload = b'\xc4' + scriptHash  # 0xc4 is the version byte for testnet P2SH
        checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
        binary_address = version_payload + checksum
        return base58.b58encode(binary_address).decode('utf-8')

    def public_key_to_bech32_address(self, public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = ripemd160(sha256_hash)
        return bech32.encode('tb', 0, ripemd160_hash)

    def generate_addresses(self, num_addresses=20):
        for account in range(3):  # Derive for 3 accounts
            for address_type in [44, 49, 84]:  # BIP44 (P2PKH), BIP49 (P2SH-P2WPKH), BIP84 (P2WPKH)
                for i in range(num_addresses):
                    path = [0x80000000 | address_type, 0x80000001, 0x80000000 | account, 0, i]
                    key = self.derive_path(path)
                    public_key = self.private_to_public(key['private_key'])
                    
                    if address_type == 44:
                        address = self.public_key_to_p2pkh_address(public_key)
                        address_type_str = "P2PKH"
                    elif address_type == 49:
                        address = self.public_key_to_p2sh_address(public_key)
                        address_type_str = "P2SH-P2WPKH"
                    else:
                        address = self.public_key_to_bech32_address(public_key)
                        address_type_str = "P2WPKH"

                    self.addresses.append({
                        "path": f"m/{address_type}'/1'/{account}'/0/{i}",
                        "address": address,
                        "type": address_type_str
                    })
    async def ensure_electrum_client(self):
        if self.electrum_client is None:
            self.electrum_client = ElectrumClient()
            await self.electrum_client.connect()
    async def get_balance(self, address):
        await self.ensure_electrum_client()
        try:
            balance = await self.electrum_client.get_balance(address)
            confirmed = balance['confirmed'] / 100000000  # Convert satoshis to BTC
            unconfirmed = balance['unconfirmed'] / 100000000
            logger.info(f"Balance for {address}: {confirmed} BTC (confirmed), {unconfirmed} BTC (unconfirmed)")
            return confirmed, unconfirmed
        except Exception as e:
            logger.error(f"Error fetching balance for {address}: {str(e)}")
            return 0, 0

    async def get_all_balances(self):
        await self.ensure_electrum_client()
        total_confirmed = 0
        total_unconfirmed = 0
        for addr_info in self.addresses:
            confirmed, unconfirmed = await self.get_balance(addr_info['address'])
            addr_info['confirmed_balance'] = confirmed
            addr_info['unconfirmed_balance'] = unconfirmed
            total_confirmed += confirmed
            total_unconfirmed += unconfirmed
        return total_confirmed, total_unconfirmed

    def load_wallet(self, password):
        with open(self.wallet_file, 'rb') as file:
            data = file.read()
        salt = data[:16]
        encrypted_mnemonic = data[16:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        try:
            decrypted_mnemonic = f.decrypt(encrypted_mnemonic)
            return decrypted_mnemonic.decode()
        except:
            raise ValueError("Invalid password or corrupted wallet file.")

async def main():
    wallet = BitcoinTestnetHDWallet()

    # Load existing wallet
    password = input("Enter your wallet password: ")
    try:
        wallet.load_existing_wallet(password)
        print("Wallet loaded successfully.")
    except Exception as e:
        print(f"Error loading wallet: {str(e)}")
        return

    # Generate addresses
    wallet.generate_addresses()

    # Show all funds
    print("Fetching balances. This may take a while...")
    total_confirmed, total_unconfirmed = await wallet.get_all_balances()
    print(f"\nTotal wallet balance: {total_confirmed:.8f} BTC (confirmed), {total_unconfirmed:.8f} BTC (unconfirmed)")
    for addr_info in wallet.addresses:
        if addr_info['confirmed_balance'] > 0 or addr_info['unconfirmed_balance'] > 0:
            print(f"Path: {addr_info['path']}")
            print(f"Address ({addr_info['type']}): {addr_info['address']}")
            print(f"Confirmed Balance: {addr_info['confirmed_balance']:.8f} BTC")
            print(f"Unconfirmed Balance: {addr_info['unconfirmed_balance']:.8f} BTC")
            print()

    if wallet.electrum_client:
        await wallet.electrum_client.close()

if __name__ == "__main__":
    asyncio.run(main())
