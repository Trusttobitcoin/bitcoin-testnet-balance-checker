# Bitcoin Testnet Balance Checker

A Python-based tool for checking Bitcoin testnet balances using HD wallet derivation and Electrum server integration.

## Description

This tool provides a comprehensive solution for managing and checking balances of Bitcoin testnet wallets. It combines HD (Hierarchical Deterministic) wallet functionality with Electrum server integration to offer a robust set of features for developers and testers working with Bitcoin's testnet.

## Important: Wallet Encryption Prerequisite

⚠️ **Before using this tool, you must create an encrypted wallet file (`wallet.enc`).**

To create the required `wallet.enc` file, please visit:

[**Bitcoin-Testnet-HD-Wallet-Address-Generator**](https://github.com/Trusttobitcoin/Bitcoin-Testnet-HD-Wallet-Address-Generator)

Follow the instructions in the above repository to generate your encrypted wallet file.




## Usage

1. Ensure you have created the `wallet.enc` file using the [Bitcoin-Testnet-HD-Wallet-Address-Generator](https://github.com/Trusttobitcoin/Bitcoin-Testnet-HD-Wallet-Address-Generator).

2. Place your `wallet.enc` file in the same directory as the script.

3. Run the script:
   ```
   python bitcoin_testnet_balance_checker.py
   ```

4. Follow the prompts to load your wallet and check balances.

## Security Note

This tool is designed for use with Bitcoin's testnet only. It should not be used with real (mainnet) Bitcoin without proper security audits and modifications. Always exercise caution when dealing with cryptocurrency wallets and private keys.


## License

[MIT](https://choosealicense.com/licenses/mit/)

