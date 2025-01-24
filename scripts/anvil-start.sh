#!/bin/sh

# Define your custom mnemonic
MNEMONIC="fruit rate region anchor capable they tennis slam embrace gossip neither glue"

# Define the number of accounts you want to create
NUM_ACCOUNTS=15

# Define the balance for each account (in Ether)
ACCOUNT_BALANCE="20000"  # 20,000 ETH

# Start Anvil with the custom mnemonic, number of accounts, and account balance
anvil --mnemonic "$MNEMONIC" --accounts $NUM_ACCOUNTS --balance $ACCOUNT_BALANCE --host 0.0.0.0 --port 8545
