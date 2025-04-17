#!/bin/bash

# Usage:
# ./anvil-skip-to-block.sh 57 http://localhost:8545

# Check if target block number is passed as the first argument
if [ -z "$1" ]; then
  echo "Usage: $0 TARGET_BLOCK_NUMBER [RPC_URL]"
  exit 1
fi

# Assign the command line input to TARGET_BLOCK_NUMBER
TARGET_BLOCK_NUMBER=$1

# Assign the second argument as the RPC URL (default to http://localhost:8545 if not provided)
RPC_URL=${2:-http://localhost:8545}

# Print the RPC URL being used (for debugging)
echo "Using RPC URL: $RPC_URL"

# Get the current block number from the specified RPC URL
current_block=$(cast block-number --rpc-url "$RPC_URL")

# Ensure current_block is not empty or invalid
if [ -z "$current_block" ]; then
  echo "Failed to retrieve the current block number."
  exit 1
fi

# Print the current block number for debugging purposes
echo "Current block: $current_block"

# Calculate the number of blocks to skip
blocks_to_skip=$((TARGET_BLOCK_NUMBER - current_block))

# Ensure blocks_to_skip is positive
if [ "$blocks_to_skip" -le 0 ]; then
  echo "Current block ($current_block) is already at or beyond target block ($TARGET_BLOCK_NUMBER)."
  exit 1
fi

# Print the number of blocks to skip
echo "Blocks to skip: $blocks_to_skip"

# Mine blocks to reach the target block
for _ in $(seq 1 $blocks_to_skip); do
  # Run the mine command and suppress any output
  cast rpc --rpc-url "$RPC_URL" anvil_mine > /dev/null 2>&1

  # Optionally, you can add feedback on progress
  echo "Mining block..."
done

# Get the new current block number after mining
new_block=$(cast block-number --rpc-url "$RPC_URL")

# Check if we reached the target block
if [ "$new_block" -eq "$TARGET_BLOCK_NUMBER" ]; then
  echo "Reached target block number: $TARGET_BLOCK_NUMBER"
else
  echo "Error: Did not reach the target block. Current block is $new_block, expected $TARGET_BLOCK_NUMBER."
  exit 1
fi
