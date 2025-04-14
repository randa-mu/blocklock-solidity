# blocklock-solidity

[![Solidity ^0.8.x](https://img.shields.io/badge/Solidity-%5E0.8.x-blue)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Tested%20with-Foundry-red)](https://book.getfoundry.sh/)

A Solidity library enabling on-chain timelock encryption and decryption, from the [dcipher threshold network](https://dcipher.network/). This facilites secure time-based data unlocking mechanisms for smart contracts.

## Overview

Controlling access to data based on time is crucial for various use cases, such as auctions, voting, and content release schedules. `blocklock-solidity` provides developers with tools to implement timelock encryption, ensuring that encrypted data can only be decrypted after a specified block number, thus enhancing security and fairness in time-sensitive operations.

[placeholder for explaining blocklock]
- the libraries
- the contracts

The library is designed with modularity and simplicity in mind, allowing developers to easily integrate it into their existing smart contract projects. Its extensible architecture makes it suitable for a wide range of applications that require robust on-chain randomness.

## Features

Powered by the dcipher threshold network and its threshold-based cryptographic schemes, this library offers:
* **Timelock Encryption**: Encrypt data that can only be decrypted after a specified block number.
* **Decryption**: Implement custom logic that gets triggered when the decryption key is received, i.e., decryption of the Ciphertext.
* **Modular**: Supports pluggable signature schemes for verifying decryption keys, enabling flexible cryptographic backends.

## Smart Contracts    

### Timelock
Provides functionality to schedule encrypted data to be decrypted only after a certain block number.
* ✨ `AbstractBlocklockReceiver.sol` - An abstract contract that developers must extend to request timelock encryption and receive decrypted data in their smart contracts.
* `BlocklockSender.sol` - Handles creation and tracking of timelock encryption requests.
* `DecryptionSender.sol` - Delivers decryption keys to receivers once the unlock block is reached and the key is verified.

### Signature
Since decryption keys must be securely verified, this library also includes contracts for requesting and processing signature requests using a defined schema.
* `BlocklockSignatureScheme.sol` - A signature verification module for validating decryption keys using defined criteria.
* `DecryptionReceiverBase.sol` - An abstract contract that handles receiving and decoding decryption key deliveries. Ideal if your contract does not need to send timelock requests, but still needs to respond to key delivery.
* `SignatureSchemeAddressProvider.sol` - Maintains the list of supported signature schemes (e.g., BLS).

> 💡 **Note:** You only need to extend `AbstractBlocklockReceiver.sol` to integrate timelock encryption into your contracts. All other required contracts are already deployed on supported networks.

### Supported Networks

#### Filecoin Calibnet

| Contract                        | Address                                                                                                                             |
|---------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| **✨ BlocklockSender (Proxy)** | [0xfF66908E1d7d23ff62791505b2eC120128918F44](https://calibration.filfox.info/en/address/0xfF66908E1d7d23ff62791505b2eC120128918F44)   |
| BlocklockSender (Impl) | [0x02097463c21f21214499FAa538240029d2e4A220](https://calibration.filfox.info/en/address/0x02097463c21f21214499FAa538240029d2e4A220)   |
| DecryptionSender (Proxy) | [0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3](https://calibration.filfox.info/en/address/0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3)   |
| DecryptionSender (Impl) | [0xea9111e44D23029945f2E46b2bFf26b04D15bd6F](https://calibration.filfox.info/en/address/0xea9111e44D23029945f2E46b2bFf26b04D15bd6F)   |
| SignatureSchemeAddressProvider | [0xD2b5084E68230D609AEaAe5E4cF7df9ebDd6375A](https://calibration.filfox.info/en/address/0xD2b5084E68230D609AEaAe5E4cF7df9ebDd6375A)   |
| BlocklockSignatureScheme | [0x62C9CF8Ff30177d8479eDaB017f38017bEbf10C2](https://calibration.filfox.info/en/address/0x62C9CF8Ff30177d8479eDaB017f38017bEbf10C2)   |

> 💡 **Note:** `BlocklockSender.sol` is the only contract developers need to interact with directly when creating timelock requests, as it abstracts the underlying implementation and upgradeability via proxy.

[WIP testing these and reformat to quickstart] 

### Using the Solidity Interfaces

#### Installation

##### Hardhat (npm)

```sh
$ npm install blocklock-solidity
```

##### Foundry 
```sh
$ forge install randa-mu/blocklock-solidity
```

#### Importing

To use this library in your project, import the required files into your contract and use the proxy contract address for BlocklockSender in the constructor as the blocklockContract parameter:

```solidity
// Import the Types library for managing ciphertexts
import {TypesLib} from "blocklock-solidity/src/libraries/TypesLib.sol";
// Import the AbstractBlocklockReceiver for handling timelock decryption callbacks
import {AbstractBlocklockReceiver} from "blocklock-solidity/src/AbstractBlocklockReceiver.sol";
```

#### Example Usage

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TypesLib} from "blocklock-solidity/src/libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "blocklock-solidity/src/AbstractBlocklockReceiver.sol";

contract MockBlocklockReceiver is AbstractBlocklockReceiver {
    uint256 public requestId;
    TypesLib.Ciphertext public encryptedValue;
    uint256 public plainTextValue;

    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}

    function createTimelockRequest(uint256 decryptionBlockNumber, TypesLib.Ciphertext calldata encryptedData)
        external
        returns (uint256)
    {
        // Create timelock request
        requestId = blocklock.requestBlocklock(decryptionBlockNumber, encryptedData);
        // Store the Ciphertext
        encryptedValue = encryptedData;
        return requestId;
    }

    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey)
        external
        override
        onlyBlocklockContract
    {
        require(requestID == requestId, "Invalid request id");
        // Decrypt stored Ciphertext with the decryption key
        plainTextValue = abi.decode(blocklock.decrypt(encryptedValue, decryptionKey), (uint256));
    }
}
```

### How It Works

* Encryption: Use the off-chain TypeScript library to generate the encrypted data (`TypesLib.Ciphertext`) with a threshold network public key. The following solidity types are supported by the TypeScript library - uint256, int256, address, string, bool, bytes32, bytes, uint256 array, address array, and struct.
* Timelock Request: Call `blocklock.requestBlocklock` with the block number after which decryption is allowed and the encrypted data or Ciphertext.
* Decryption: Once the specified block number is reached, a callback to your `receiveBlocklock` logic is triggered with the decryption key to unlock the data.

### Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

### Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

### Acknowledgments

Special thanks to the Filecoin Foundation for supporting the development of this library.
