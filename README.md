# blocklock-solidity

[![Solidity ^0.8.x](https://img.shields.io/badge/Solidity-%5E0.8.x-blue)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Tested%20with-Foundry-red)](https://book.getfoundry.sh/)

A Solidity library enabling on-chain blocklock encryption and decryption, from the [dcipher threshold network](https://dcipher.network/). This facilitates secure time-based data unlocking mechanisms for smart contracts.

## ✨ Overview

Controlling access to data based on time is crucial for various use cases, such as auctions, voting, and content release schedules. `blocklock-solidity` provides developers with tools to implement blocklock encryption on-chain, ensuring that encrypted data can only be decrypted after a specified block height, thus enhancing security and fairness in time-sensitive operations. 

This blocklock library is powered by the dciper threshold network using **BLS pairing-based signature scheme** and **identity-based encryption** to achieve data encryption toward a future block height without relying on a trusted third party.  It is especially useful in decentralized settings where there is no such trusted third party to enforce timing.

The library is designed with modularity and simplicity in mind, allowing developers to easily integrate it into their existing smart contract projects to achieve blocklock on-chain. Its extensible architecture makes it suitable for a wide range of applications that require robust on-chain randomness.

### Features

Powered by the dcipher threshold network and its threshold-based cryptographic schemes, this library offers:
* **On-chain Blocklock Encryption**: Encrypt data that can only be decrypted after a specified block number.
* **Decryption**: Implement custom logic that gets triggered when the decryption key is received, i.e., decryption of the Ciphertext.
* **Modular**: Supports pluggable signature schemes for verifying decryption keys, enabling flexible cryptographic backends.

## 🧩 Smart Contracts    

### Blocklock
Provides functionality to schedule encrypted data to be decrypted only after a certain block number.
* ✨ `AbstractBlocklockReceiver.sol` - An abstract contract that developers must extend to request blocklock encryption and receive decrypted data in their smart contracts.
* `BlocklockSender.sol` - Handles creation and tracking of blocklock encryption requests.
* `BlocklockSignatureScheme.sol` - The `BN254-BLS-BLOCKLOCK` signature scheme for validating messaging coming from the dcipher network. This scheme is registered via `SignatureSchemeAddressProvider.sol`.

### Decryption
Since decryption keys must be securely verified based on the block condition, this library also includes contracts for requesting and processing decryption requests using a defined schema.

* `DecryptionSender.sol` - Delivers decryption keys to receivers once the unlock block is reached and the key is verified.
* `DecryptionReceiverBase.sol` - An abstract contract that handles receiving and decoding decryption key deliveries. Ideal if your contract does not need to send blocklock requests, but still needs to respond to key delivery.
* `SignatureSchemeAddressProvider.sol` - Maintains the list of supported threshold signature schemes (e.g., BLS on BN254, BLS on  BLS12-381).

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

## ⚙️ How It Works

1. **Data Encryption (off-chain)**

     Generate the encrypted data (`TypesLib.Ciphertext`) with the dcipher threshold network public key for the decryption at the desired block height, using our [blocklock.js](https://github.com/randa-mu/blocklock-js) library. 

    This TypeScript library supports the following Solidity types: `uint256`, `int256`, `address`, `string`, `bool`, `bytes32`, `bytes`, `uint256[]`, `address[]`, and `struct`.
2. **Blocklock Request**

    Interact with the on-chain contract at `blocklock.requestBlocklock()` to create a blocklock request. Submit the encrypted data and specify the chain height for decryption. After request is stored, and a `requestId` is generated for tracking.
3. **Decryption**

    Once the specified block number is reached, a callback function (`receiveBlocklock（）`) will be triggered to deliver the decryption key, allowing the unlocking of encrypted data.

## 🚀 Getting Started

### Installation
To get started, install the **blocklock-solidity** & **blocklock-js** library in your smart contract project using your preferred development tool.

**Hardhat (npm)**

```sh
$ npm install blocklock-solidity
```

**Foundry** 
```sh
$ forge install randa-mu/blocklock-solidity
```

Install **blocklock-js** so you can encrypt data in your applicatoin . 
```sh
$ npm install blocklock-js
```

### How to use

#### 1. Import the library

Start by importing the `AbstractBlocklockReceiver.sol` abstract contract into your smart contract. This contract provides the interface for making blocklock requests and handling callbacks.

```solidity
// Import the Types library for managing ciphertexts
import {TypesLib} from "blocklock-solidity/src/libraries/TypesLib.sol";
// Import the AbstractBlocklockReceiver for handling blocklock decryption & callbacks
import {AbstractBlocklockReceiver} from "blocklock-solidity/src/AbstractBlocklockReceiver.sol";
```

#### 2. Extend the AbstractBlocklockReceiver contract
Your contract must inherit from `AbstractBlocklockReceiver` and initialize with the deployed `BlocklockSender (Proxy)` contract from your desired network in the constructor.

```solidity
contract MockBlocklockReceiver is AbstractBlocklockReceiver {
    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}
    ...
}
```

#### 3. Request Blocklock encryption
Define a function to initiate blocklock encryption requests originating from your application.
In this function, interact with the deployed `BlocklockSender` contract instance to register the encryption request on-chain, as shown in the following example. 

The function should return a `requestId`, which can be stored within your contract for tracking and managing the lifecycle of the blocklock encryption request.

```solidity
function createBlocklockRequest(uint256 decryptionBlockNumber, TypesLib.Ciphertext calldata encryptedData)
        external
        returns (uint256)
    {
        // Create blocklock request
        requestId = blocklock.requestBlocklock(decryptionBlockNumber, encryptedData);
        // Store the Ciphertext
        encryptedValue = encryptedData;
        return requestId;
    }
```

#### 4. Handle the Blocklock Callback

Once the blocklock request is registered, the dcipher network will monitor the blockchain and, upon reaching the specified block height, invoke the `receiveBlocklock()` callback function of your contract to deliver the decryption key.

To handle the decryption event, you must override the `receiveBlocklock()` function within your contract and implement the desired application logic.

```solidity
function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey)
        external
        override
        onlyBlocklockContract
    {
        require(requestID == requestId, "Invalid request id");
        // Decrypt stored Ciphertext with the decryption key
        plainTextValue = abi.decode(blocklock.decrypt(encryptedValue, decryptionKey), (uint256));
    }
```
> 💡 **Note:** `blocklock.decrypt` automatically verifies the dcipher threshold decryption key for you because of the power of threshold signatures scheme!

#### 5. Deploy the `BlocklockHandler` contract
Please check the supprted network section to ensure your desired network is supported before deployment. You also need to use the deployed **BlocklockSender (Proxy)** address to initialized your contract.

When deploying, make sure your desired network is supported. Use the deployed `BlocklockSender (Proxy)` address when initializing your contract.

Example in Foundry Script for Filecoin Calibration: 
```solidity
address blocklockSenderProxy = 0xfF66908E1d7d23ff62791505b2eC120128918F44;
MockBlocklockReceiver mockBlocklockReceiver = new MockBlocklockReceiver(address(blocklockSenderProxy));
console.log("\nMockBlocklockReceiver deployed at: ", address(mockBlocklockReceiver));
```

#### 6. Off-chain data encoding and encryption
Use [blocklock.js](https://github.com/randa-mu/blocklock-js) to encode and encrypt data off-chain before calling the smart contract. It ensures data is encrypted using the dcipher threshold public key and specified block height.

Below is a sample JavaScript/TypeScript snippet:
```Javascript
import { getBytes } from "ethers";
...

// Encode the uint256 value
const encoder = new SolidityEncoder();
const msgBytes = encoder.encodeUint256(msg);
const encodedMessage = getBytes(msgBytes);

// Encrypt the encoded message
const blocklockjs = new Blocklock(wallet, <blocklockSender-contract-address>);
const ciphertext = blocklockjs.encrypt(encodedMessage, blockHeight);
```

To get a full example, please check the [example in blocklock-js](https://github.com/randa-mu/blocklock-js?tab=readme-ov-file#example-encrypting-a-uint256-4-eth-for-decryption-2-blocks-later).

#### Example Usage
To have a full example of code, please check the following links:
- The example of [MockBlocklockReceiver.sol](./src/mocks/MockBlocklockReceiver.sol) 
- The example of off-chain [data encoding and encryption](https://github.com/randa-mu/blocklock-js?tab=readme-ov-file#example-encrypting-a-uint256-4-eth-for-decryption-2-blocks-later).


## 📚 APIs
#### BlocklockSender
|Contract|Return|Description|
|--------|-----------|-------|
|`requestBlocklock(uint256 blockHeight, TypesLib.Ciphertext ciphertext)` | `uint256 requestID`|Requests the generation of a blocklock decryption key at a specific blockHeight. |
|`decrypt(TypesLib.Ciphertext ciphertext, bytes decryptionKey)` | `bytes`|Decrypt a ciphertext into a plaintext using a decryption key. |
|`getRequest(uint256 requestID)`|`TypesLib.BlocklockRequest`|Retrieves a specific blocklock request details.|
|`isInFlight(uint256 requestID)`|`bool`|Returns `true` if the specified blocklock request is pending.|

## 📜 Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

## 🤝 Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

## 🎉 Acknowledgments

Special thanks to the Filecoin Foundation for supporting the development of this library.
