# blocklock-solidity

<<<<<<< HEAD
This repository provides an easy-to-use Solidity smart contract interface that facilitates Randamu's onchain conditional encryption.

By leveraging this library, developers can implement conditional data unlocking mechanisms securely in their smart contracts.
=======
[![Solidity ^0.8.x](https://img.shields.io/badge/Solidity-%5E0.8.x-blue)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Tested%20with-Foundry-red)](https://book.getfoundry.sh/)

A Solidity library enabling on-chain timelock encryption and decryption, from the [dcipher threshold network](https://dcipher.network/). This facilitates secure time-based data unlocking mechanisms for smart contracts.
>>>>>>> main

## ✨ Overview

Controlling access to data based on time is crucial for various use cases, such as auctions, voting, and content release schedules. `blocklock-solidity` provides developers with tools to implement timelock encryption on-chain, ensuring that encrypted data can only be decrypted after a specified block height, thus enhancing security and fairness in time-sensitive operations. 

This timelock library is powered by the dcipher threshold network using **BLS pairing-based signature scheme** and **identity-based encryption** to achieve data encryption toward a future block height without relying on a trusted third party.  It is especially useful in decentralized settings where no such trusted third party enforces timing.

The library is designed with modularity and simplicity in mind, allowing developers to easily integrate it into their existing smart contract projects to achieve timelock on-chain for a wide range of applications.

### Features
<<<<<<< HEAD
* Conditional Encryption: Encrypt data that can only be decrypted after a specified condition has been met, e.g., chain height.
* Decryption Callback: Implement custom logic that gets triggered when the decryption key is received, i.e., decryption of the Ciphertext.
* Abstract Interface: Extend and implement the library to suit your specific needs.

### Installation

#### Hardhat (npm)
=======

Powered by the dcipher threshold network and its threshold-based cryptographic schemes, this library offers:
* **On-chain Timelock Encryption**: Encrypt data that can only be decrypted after a specified block number.
* **Decryption**: Implement custom logic that gets triggered when the decryption key is received, i.e., decryption of the Ciphertext.
* **Modular**: Supports pluggable signature schemes for verifying decryption keys, enabling flexible cryptographic backends.

## 🧩 Smart Contracts    

### Blocklock
Provides functionality to schedule encrypted data to be decrypted only after a certain block number.
* ✨ `AbstractBlocklockReceiver.sol` - An abstract contract that developers must extend to request timelock encryption and receive decrypted data in their smart contracts.
* `BlocklockSender.sol` - Handles creation and tracking of timelock encryption requests.
* `BlocklockSignatureScheme.sol` - The `BN254-BLS-BLOCKLOCK` signature scheme for validating messaging coming from the dcipher network. This scheme is registered via `SignatureSchemeAddressProvider.sol`.

### Decryption
Timelock decryption key is only revealed and verified once the specified block height condition is met, as determined by the dcipher threshold network.
This library includes smart contracts that enable request, receive, and verify decryption keys using supported cryptographic signature schemes. 

* `DecryptionSender.sol` - Delivers decryption keys to receivers once the unlock block is reached and the key is verified.
* `DecryptionReceiverBase.sol` - An abstract contract that handles receiving and decoding decryption key deliveries. Ideal if your contract does not need to send timelock requests, but still needs to respond to key delivery.
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
2. **Timelock Request**

    Interact with the on-chain contract at `blocklock.requestBlocklock()` to create a timelock request. Submit the encrypted data and specify the chain height for decryption. After your request is stored, a `requestId` is generated for tracking.
3. **Decryption**

    Once the specified block number is reached, a callback function (`receiveBlocklock（）`) will be triggered to deliver the decryption key, allowing the unlocking of encrypted data.

## 🚀 Getting Started

### Installation
To get started, install the **blocklock-solidity** & **blocklock-js** libraries in your smart contract project using your preferred development tool.

**Hardhat (npm)**
>>>>>>> main

```sh
npm install blocklock-solidity
```

<<<<<<< HEAD
#### Foundry 
=======
**Foundry** 
>>>>>>> main
```sh
forge install randa-mu/blocklock-solidity
```

<<<<<<< HEAD
### Usage 

#### Build
```sh
npm run build
```

#### Test
```sh
npm run test
```

#### Linting
```sh
npm run lint:fix
```

#### Code Coverage

To run foundry coverage:

```sh
FOUNDRY_PROFILE=coverage forge coverage --report summary
```

This project also includes a [coverage.sh](utils/coverage.sh) script to generate and view test coverage reports using lcov. After the script runs, it generates and opens a html page showing lines of code covered by tests and those that have not been covered. If lcov is not installed, the script will attempt to install it automatically using Homebrew (macOS) or apt (Linux).

To make the script executable:

```sh
chmod +x dev/coverage.sh
```

To run the script:

```sh
./dev/coverage.sh
```


### Deployment 

For deployment steps, please see [deployment documentation](script/README.md).

### Supported Networks

| Contract        |  Description | Address | 
|-----------------|---------|---------|
| **BlocklockSender Proxy** | A lightweight proxy contract that enables upgradeability for the `BlocklockSender` implementation. It delegates all calls to the underlying implementation and serves as the primary interface for user interaction. | <br>- Filecoin Calibration Testnet: [0xF8e2477647Ee6e33CaD4C915DaDc030b74AB976b](https://calibration.filfox.info/en/address/0xF8e2477647Ee6e33CaD4C915DaDc030b74AB976b)<br> - Base Sepolia: [0x14bFdD6D5C1E639bbC1F262a48217Ff6925e4197](https://sepolia.basescan.org/address/0x14bFdD6D5C1E639bbC1F262a48217Ff6925e4197) <br> - Polygon PoS: [0x14bFdD6D5C1E639bbC1F262a48217Ff6925e4197](https://polygonscan.com/address/0x14bFdD6D5C1E639bbC1F262a48217Ff6925e4197) <br> | 
| BlocklockSender Implementation | Handles conditional encryption requests, callbacks, and fee collection. | <br>- Filecoin Calibration Testnet: [0x6C2100334F96c9A845275Df881d7E087bddd96c6](https://calibration.filfox.info/en/address/0x6C2100334F96c9A845275Df881d7E087bddd96c6)<br> - Base Sepolia: [0x5c73E120d9d7090594355705fcE5a455Bd777300](https://sepolia.basescan.org/address/0x5c73E120d9d7090594355705fcE5a455Bd777300) <br> - Polygon PoS: [0x5c73E120d9d7090594355705fcE5a455Bd777300](https://polygonscan.com/address/0x5c73E120d9d7090594355705fcE5a455Bd777300) | 
| DecryptionSender Proxy | Upgradeable proxy for DecryptionSender. | <br>- Filecoin Calibration Testnet:[0xdAe4d67C68d7550bb39e1B394E99Bc7AA2eDC601](https://calibration.filfox.info/en/address/0xdAe4d67C68d7550bb39e1B394E99Bc7AA2eDC601)<br> - Base Sepolia: [0x558756C3f750e8a6e3c800CD03C66396612a4f51](https://sepolia.basescan.org/address/0x558756C3f750e8a6e3c800CD03C66396612a4f51) <br> - Polygon PoS: [0x558756C3f750e8a6e3c800CD03C66396612a4f51](https://polygonscan.com/address/0x558756C3f750e8a6e3c800CD03C66396612a4f51)| 
| DecryptionSender Implementation | Contract used by offchain oracle to fulfill conditional encryption requests. | <br>- Filecoin Calibration Testnet: [0xc11eC0D11A8F93dB5807A631D64faf85230667F4](https://calibration.filfox.info/en/address/0xc11eC0D11A8F93dB5807A631D64faf85230667F4)<br> - Base Sepolia: [0x04c7f7375B55ae7A2d42D31654Bf1F9496741EB9](https://sepolia.basescan.org/address/0x04c7f7375B55ae7A2d42D31654Bf1F9496741EB9) <br> - Polygon PoS: [0x04c7f7375B55ae7A2d42D31654Bf1F9496741EB9](https://polygonscan.com/address/0x04c7f7375B55ae7A2d42D31654Bf1F9496741EB9) | 
| SignatureSchemeAddressProvider | Stores contract addresses for signature schemes. | <br>- Filecoin Calibration Testnet: [0x5F8470D50cA16f4a69d6346a3F77b256A4492b49](https://calibration.filfox.info/en/address/0x5F8470D50cA16f4a69d6346a3F77b256A4492b49)<br> - Base Sepolia: [0x25F7C52fC392022182ac38AB33Ba1d49221B8da9](https://sepolia.basescan.org/address/0x25F7C52fC392022182ac38AB33Ba1d49221B8da9) <br> - Polygon PoS: [0x25F7C52fC392022182ac38AB33Ba1d49221B8da9](https://polygonscan.com/address/0x25F7C52fC392022182ac38AB33Ba1d49221B8da9) | 
| BlocklockSignatureScheme | BN254 pairing-based signature verifier. | <br>- Filecoin Calibration Testnet: [0x73445432d11253624EE59fe3Ad53aB1d8b32700c](https://calibration.filfox.info/en/address/0x73445432d11253624EE59fe3Ad53aB1d8b32700c)<br> - Base Sepolia: [0x0D504971B9A142b8f6844c56Db42464C29499990](https://sepolia.basescan.org/address/0x0D504971B9A142b8f6844c56Db42464C29499990) <br> - Polygon PoS: [0x0D504971B9A142b8f6844c56Db42464C29499990](https://polygonscan.com/address/0x0D504971B9A142b8f6844c56Db42464C29499990) | 


### Using the Solidity Interface


#### Importing the Interface

To use this abstract contract in your project, the first step is to import the required files into your contract and use the proxy contract address for BlocklockSender in the constructor as the blocklockContract parameter:
=======
Install **blocklock-js** so you can encrypt data in your application. 
```sh
$ npm install blocklock-js
```

### How to use

#### 1. Import the library

Start by importing the `AbstractBlocklockReceiver.sol` abstract contract into your smart contract. This contract provides the interface for making timelock requests and handling callbacks.
>>>>>>> main

```solidity
// Import the Types library for managing ciphertexts
import {TypesLib} from "blocklock-solidity/src/libraries/TypesLib.sol";
// Import the AbstractBlocklockReceiver for handling blocklock decryption & callbacks
import {AbstractBlocklockReceiver} from "blocklock-solidity/src/AbstractBlocklockReceiver.sol";
```

#### 2. Extend the AbstractBlocklockReceiver contract
Your contract must inherit from `AbstractBlocklockReceiver` and initialize with the deployed `BlocklockSender (Proxy)` contract from your desired network in the constructor.

An example decryption key `receiver` contract [MockBlocklockReceiver.sol](src/mocks/MockBlocklockReceiver.sol) has been provided in the `src/mocks` folder. It inherits from the [AbstractBlocklockReceiver](src/AbstractBlocklockReceiver.sol) base contract.

The contract makes conditional encryption requests for an `uint256` value.

Requests can be funded in two ways: 
1. Direct funding
2. Subscription account


##### Direct Funding 

The following internal function allows the smart contract to make requests without an active subscription. 

```solidity
<<<<<<< HEAD
/// @notice Requests a blocklock without a subscription and returns the request ID and request price.
/// @dev This function calls the `requestBlocklock` function from the `blocklock` contract, passing the required parameters such as
///      `callbackGasLimit`, `blockHeight`, and `ciphertext`.
/// @param callbackGasLimit The gas limit for the callback function to be executed after the blocklock request.
/// @param blockHeight The block height for which the blocklock request is made.
/// @param ciphertext The ciphertext to be used in the blocklock request.
/// @notice This function internally calls the `blocklock.requestBlocklock` function.
function _requestBlocklockPayInNative(
    uint32 callbackGasLimit,
    uint256 blockHeight,
    TypesLib.Ciphertext calldata ciphertext
) internal returns (uint256 requestId, uint256 requestPrice) {
    requestPrice = blocklock.calculateRequestPriceNative(callbackGasLimit);
    return
        (blocklock.requestBlocklock{value: requestPrice}(callbackGasLimit, blockHeight, ciphertext), requestPrice);
}
```
The function returns the request id and request price in wei.

Please note that to make a request via this function, the smart contract should be pre-funded with native tokens / ETH enough to fund the request price.

To fund the contract, the following function can be used (also inherited from [AbstractBlocklockReceiver.sol](src/AbstractBlocklockReceiver.sol)):

```solidity
/// @notice Function to fund the contract with native tokens for direct funding requests.
function fundContractNative() external payable {
    require(msg.value > 0, "You must send some ETH");
    emit Funded(msg.sender, msg.value);
}
```

The contract can be funded by anyone and can also be funded via direct native token / Ether transfer to its address.

To determine the request price prior to the request, the following function in the `BlocklockSender` contract interface can be used to fetch an estimated price:

```solidity
/// @notice Calculates the estimated price in native tokens for a request based on the provided gas limit
/// @param _callbackGasLimit The gas limit for the callback execution
/// @return The estimated request price in native token (e.g., ETH)
function calculateRequestPriceNative(uint32 _callbackGasLimit) external view returns (uint256);
```


##### Subscription Account 

To create requests with a subscription account, the subscription account should be created and pre-funded to cover for requests. A subscription account or id can be shared with multiple decryption key `receiver` smart contracts as well.

To create a subscription, the following function in [AbstractBlocklockReceiver.sol](src/AbstractBlocklockReceiver.sol) is used:

```solidity
/// @notice Creates and funds a new Randamu subscription using native currency.
/// @dev Only callable by the contract owner. If a subscription already exists, it will not be recreated.
/// @dev The ETH value sent in the transaction (`msg.value`) will be used to fund the subscription.
function createSubscriptionAndFundNative() external payable onlyOwner {
    subscriptionId = _subscribe();
    blocklock.fundSubscriptionWithNative{value: msg.value}(subscriptionId);
}
```

It sets the `subscriptionId` variable in the contract which is used to make subscription funded requests when the function below is called:

```solidity
/// @notice Requests a blocklock with a subscription and returns the request ID.
/// @dev This function calls the `requestBlocklockWithSubscription` function from the `blocklock` contract, passing the required parameters such as
///      `callbackGasLimit`, `subscriptionId`, `blockHeight`, and `ciphertext`.
/// @param callbackGasLimit The gas limit for the callback function to be executed after the blocklock request.
/// @param blockHeight The block height for which the blocklock request is made.
/// @param ciphertext The ciphertext to be used in the blocklock request.
/// @return requestId The unique identifier for the blocklock request.
/// @notice This function internally calls the `blocklock.requestBlocklockWithSubscription` function.
function _requestBlocklockWithSubscription(
    uint32 callbackGasLimit,
    uint256 blockHeight,
    TypesLib.Ciphertext calldata ciphertext
) internal returns (uint256 requestId) {
    return blocklock.requestBlocklockWithSubscription(callbackGasLimit, subscriptionId, blockHeight, ciphertext);
}
```


###### Sharing Subscription Accounts 

To share a subscription account, the smart contract that owns the subscription needs to call the `updateSubscription` function to approve other contracts to use it's created subscription id.

```solidity
/// @notice Adds a list of consumer addresses to the Randamu subscription.
/// @dev Requires the subscription ID to be set before calling.
/// @param consumers An array of addresses to be added as authorized consumers.
function updateSubscription(address[] calldata consumers) external onlyOwner {
    require(subscriptionId != 0, "subID not set");
    for (uint256 i = 0; i < consumers.length; i++) {
        blocklock.addConsumer(subscriptionId, consumers[i]);
=======
contract MockBlocklockReceiver is AbstractBlocklockReceiver {
    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}
    ...
}
```

#### 3. Request Timelock encryption
Define a function to initiate timelock encryption requests originating from your application.
In this function, interact with the deployed `BlocklockSender` contract instance to register the encryption request on-chain, as shown in the following example. 

The function should return a `requestId`, which can be stored within your contract for tracking and managing the lifecycle of the timelock encryption request.

```solidity
function createBlocklockRequest(uint256 decryptionBlockNumber, TypesLib.Ciphertext calldata encryptedData)
        external
        returns (uint256)
    {
        // Create timelock request
        requestId = blocklock.requestBlocklock(decryptionBlockNumber, encryptedData);
        // Store the Ciphertext
        encryptedValue = encryptedData;
        return requestId;
    }
```

#### 4. Handle the timelock Callback

Once the timelock request is registered, the dcipher network will monitor the blockchain and, upon reaching the specified block height, invoke the `receiveBlocklock()` callback function of your contract to deliver the decryption key.

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
>>>>>>> main
    }
```
> 💡 **Note:** `blocklock.decrypt` automatically verifies the dcipher threshold decryption key for you because of the power of the threshold signatures scheme!

#### 5. Deploy the `BlocklockHandler` contract
Please check the supported network section to ensure your desired network is supported before deployment. You also need to use the deployed **BlocklockSender (Proxy)** address to initialize your contract.

Example in Foundry Script for Filecoin Calibration: 
```solidity
address blocklockSenderProxy = 0xfF66908E1d7d23ff62791505b2eC120128918F44;
MockBlocklockReceiver mockBlocklockReceiver = new MockBlocklockReceiver(address(blocklockSenderProxy));
console.log("\nMockBlocklockReceiver deployed at: ", address(mockBlocklockReceiver));
```

<<<<<<< HEAD
After calling `updateSubscription` all approved contracts can then call the `setSubId` function and start making subscription funded conditional encryption requests using the shared subscription account. 

```solidity
/// @notice Sets the Randamu subscription ID used for conditional encryption oracle services.
/// @dev Only callable by the contract owner.
/// @param subId The new subscription ID to be set.
function setSubId(uint256 subId) external onlyOwner {
    subscriptionId = subId;
    emit NewSubscriptionId(subId);
}
```

Please note that all approved contracts must also implement [AbstractBlocklockReceiver.sol](src/AbstractBlocklockReceiver.sol).


#### How It Works

* Encryption: Use the off-chain TypeScript library ([blocklock-js](https://github.com/randa-mu/blocklock-js)) to generate the encrypted data (`TypesLib.Ciphertext`) with a threshold network public key. The following solidity types are supported by the TypeScript library - uint256, int256, address, string, bool, bytes32, bytes, uint256[], address[], and struct.
* Timelock Request: Call `requestBlocklock` with the chain height after which decryption is allowed and the encrypted data or Ciphertext.
* Decryption: Once the specified chain height is reached, a callback to your `receiveBlocklock` logic is triggered with the decryption key to unlock the data.
=======
#### 6. Off-chain data encoding and encryption
Use [blocklock.js](https://github.com/randa-mu/blocklock-js) to encode and encrypt data off-chain before calling the smart contract. It ensures data is encrypted using the dcipher threshold public key and specified block height.

Below is a sample JavaScript/TypeScript snippet:
```Javascript
import { getBytes } from "ethers";
...
>>>>>>> main

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
|`requestBlocklock(uint256 blockHeight, TypesLib.Ciphertext ciphertext)` | `uint256 requestID`|Requests the generation of a timelock decryption key at a specific blockHeight. |
|`decrypt(TypesLib.Ciphertext ciphertext, bytes decryptionKey)` | `bytes`|Decrypt a ciphertext into a plaintext using a decryption key. |
|`getRequest(uint256 requestID)`|`TypesLib.BlocklockRequest`|Retrieves a specific timelock request details.|
|`isInFlight(uint256 requestID)`|`bool`|Returns `true` if the specified timelock request is pending.|

## 📜 Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

## 🤝 Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

## 🎉 Acknowledgments

Special thanks to the Filecoin Foundation for supporting the development of this library.
