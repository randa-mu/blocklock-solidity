# blocklock-solidity

[![Solidity ^0.8.x](https://img.shields.io/badge/Solidity-%5E0.8.x-blue)](https://soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Foundry Tests](https://img.shields.io/badge/Tested%20with-Foundry-red)](https://book.getfoundry.sh/)

A Solidity library for secure, on-chain timelock encryption and decryption, powered by the [dcipher threshold network](https://dcipher.network/). It enables smart contracts to unlock sensitive data based on predefined conditions.

## ✨ Overview

Controlling access to data based on time (and other conditions, e.g., contract events) is crucial for various use cases, such as auctions, voting, and content release schedules. `blocklock-solidity` provides developers with tools to implement conditional encryption on-chain, ensuring that encrypted data can only be decrypted after a specified condition has been met, thus enhancing security and fairness in for example, time-sensitive operations. 

This conditional encryption library is powered by the dcipher threshold network using **BLS pairing-based signature scheme** and **identity-based encryption** to achieve data encryption toward a condition without relying on a trusted third party.

The library is designed with modularity and simplicity in mind, allowing developers to easily integrate it into their existing smart contract projects to achieve conditional encryption on-chain for a wide range of applications, e.g., timelock encryption based on a predefined future chain height.

### Features
* Conditional Encryption: Encrypt data that can only be decrypted after a specified condition has been met, e.g., chain height.
* Decryption Callback: Implement custom logic that gets triggered when the decryption key is received, i.e., decryption of the Ciphertext.
* Abstract Interface: Extend and implement the library to suit your specific needs.

### Installation

#### Hardhat (npm)

```sh
npm install blocklock-solidity
```

#### Foundry 
```sh
forge install randa-mu/blocklock-solidity
```

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

This project also includes a [coverage.sh](utils/coverage.sh) script to generate and view test coverage reports using lcov. After the script runs, it generates and opens an html coverage report. If lcov is not installed, the script will attempt to install it automatically using Homebrew (macOS) or apt (Linux).

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
| **BlocklockSender Proxy** | A lightweight proxy contract that enables upgradeability for the `BlocklockSender` implementation. It delegates all calls to the underlying implementation and serves as the primary interface for user interaction. | <br>- Filecoin Mainnet: [0x34092470CC59A097d770523931E3bC179370B44b](https://filfox.info/en/address/0x34092470CC59A097d770523931E3bC179370B44b) <br>- Filecoin Calibration Testnet: [0xF00aB3B64c81b6Ce51f8220EB2bFaa2D469cf702](https://calibration.filfox.info/en/address/0xF00aB3B64c81b6Ce51f8220EB2bFaa2D469cf702)<br> - Base Sepolia: [0x82Fed730CbdeC5A2D8724F2e3b316a70A565e27e](https://sepolia.basescan.org/address/0x82Fed730CbdeC5A2D8724F2e3b316a70A565e27e) <br> - Polygon PoS: [0x82Fed730CbdeC5A2D8724F2e3b316a70A565e27e](https://polygonscan.com/address/0x82Fed730CbdeC5A2D8724F2e3b316a70A565e27e) <br> | 
| BlocklockSender Implementation | Handles conditional encryption requests, callbacks, and fee collection. | <br>- Filecoin Mainnet: [0x9763801c3D61e079298e867DE2d1c77e2EA61D28](https://filfox.info/en/address/0x9763801c3D61e079298e867DE2d1c77e2EA61D28) <br>- Filecoin Calibration Testnet: [0x8b1a230003E7572fC069013d1050B2236e93cD90](https://calibration.filfox.info/en/address/0x8b1a230003E7572fC069013d1050B2236e93cD90)<br> - Base Sepolia: [0xd94C3A932F1bCEc4a03703f798B23142BFb0892b](https://sepolia.basescan.org/address/0xd94C3A932F1bCEc4a03703f798B23142BFb0892b) <br> - Polygon PoS: [0xd94C3A932F1bCEc4a03703f798B23142BFb0892b](https://polygonscan.com/address/0xd94C3A932F1bCEc4a03703f798B23142BFb0892b) | 
| DecryptionSender Proxy | Upgradeable proxy for DecryptionSender. | <br>- Filecoin Mainnet: [0x3436e0328A07EaE6e65D09692d09FEd7B606D113](https://filfox.info/en/address/0x3436e0328A07EaE6e65D09692d09FEd7B606D113)<br>- Filecoin Calibration Testnet:[0x2474d71AB97F1189D0E0cc1b6EbF8118DCa83000](https://calibration.filfox.info/en/address/0x2474d71AB97F1189D0E0cc1b6EbF8118DCa83000)<br> - Base Sepolia: [0x41cF74811B6B326bAe4AC4Df5b829035CB8a05DA](https://sepolia.basescan.org/address/0x41cF74811B6B326bAe4AC4Df5b829035CB8a05DA) <br> - Polygon PoS: [0x41cF74811B6B326bAe4AC4Df5b829035CB8a05DA](https://polygonscan.com/address/0x41cF74811B6B326bAe4AC4Df5b829035CB8a05DA)| 
| DecryptionSender Implementation | Contract used by offchain oracle to fulfill conditional encryption requests. | <br>- Filecoin Mainnet: [0x7bedcA667b0A2E1E2Df5C6bC799D77f8406c1f17](https://filfox.info/en/address/0x7bedcA667b0A2E1E2Df5C6bC799D77f8406c1f17)<br>- Filecoin Calibration Testnet: [0x16Ef653D1E22Aa480d7362e1827a66d42FE13505](https://calibration.filfox.info/en/address/0x16Ef653D1E22Aa480d7362e1827a66d42FE13505)<br> - Base Sepolia: [0x1723Eed061693B824ea72FCc8649Cd1a36Eb5ffC](https://sepolia.basescan.org/address/0x1723Eed061693B824ea72FCc8649Cd1a36Eb5ffC) <br> - Polygon PoS: [0x1723Eed061693B824ea72FCc8649Cd1a36Eb5ffC](https://polygonscan.com/address/0x1723Eed061693B824ea72FCc8649Cd1a36Eb5ffC) | 
| SignatureSchemeAddressProvider | Stores contract addresses for signature schemes. | <br>- Filecoin Mainnet: [0xe5609B157E5a129F48ebb06F4DB038ae50e670e1](https://filfox.info/en/address/0xe5609B157E5a129F48ebb06F4DB038ae50e670e1) <br>- Filecoin Calibration Testnet: [0x8FfAC50890C815497a90f98055E24A4192554656](https://calibration.filfox.info/en/address/0x8FfAC50890C815497a90f98055E24A4192554656)<br> - Base Sepolia: [0x141D14F91Fd43e37D090ddfF27aC2383c593bD09](https://sepolia.basescan.org/address/0x141D14F91Fd43e37D090ddfF27aC2383c593bD09) <br> - Polygon PoS: [0x141D14F91Fd43e37D090ddfF27aC2383c593bD09](https://polygonscan.com/address/0x141D14F91Fd43e37D090ddfF27aC2383c593bD09) | 
| BlocklockSignatureScheme | BN254 pairing-based signature verifier. | <br>- Filecoin Mainnet: [0x7f3303DCa853c7da34A1Eb1d6D8Fce9dF92F117A](https://filfox.info/en/address/0x7f3303DCa853c7da34A1Eb1d6D8Fce9dF92F117A) <br>- Filecoin Calibration Testnet: [0xeaeF6fC2Ee2360a4271798C4c7870F7D3C2a64e9](https://calibration.filfox.info/en/address/0xeaeF6fC2Ee2360a4271798C4c7870F7D3C2a64e9)<br> - Base Sepolia: [0x4Df133029f01959Da8d0aD13493309E7F453F796](https://sepolia.basescan.org/address/0x4Df133029f01959Da8d0aD13493309E7F453F796) <br> - Polygon PoS: [0x4Df133029f01959Da8d0aD13493309E7F453F796](https://polygonscan.com/address/0x4Df133029f01959Da8d0aD13493309E7F453F796) | 


### Using the Solidity Interface


#### 1. Importing the Interface

To use this abstract contract in your project, the first step is to import the required files into your contract and use the proxy contract address for BlocklockSender in the constructor as the blocklockContract parameter:

```solidity
// Import the Types library for managing ciphertexts
import {TypesLib} from "blocklock-solidity/src/libraries/TypesLib.sol";
// Import the AbstractBlocklockReceiver for handling blocklock decryption & callbacks
import {AbstractBlocklockReceiver} from "blocklock-solidity/src/AbstractBlocklockReceiver.sol";
```

#### 2. Extend the AbstractBlocklockReceiver contract
Your contract must inherit from `AbstractBlocklockReceiver` and initialize with the deployed `BlocklockSender (Proxy)` contract from your desired network in the constructor.

For a full example contract, please see [MockBlocklockReceiver.sol](src/mocks/MockBlocklockReceiver.sol) in the `src/mocks` folder. It inherits from the [AbstractBlocklockReceiver](src/AbstractBlocklockReceiver.sol) base contract.

The contract makes conditional encryption requests using the Ciphertext representing a `uint256` variable.

There are two options for funding conditional encryption requests, including: 
1. Direct funding, and
2. Subscription account


##### Direct Funding 

The following internal function allows the smart contract to make requests without an active subscription. 

```solidity
/// @notice Requests a blocklock without a subscription and returns the request ID and request price.
/// @dev This function calls the `requestBlocklock` function from the `blocklock` contract, passing the required parameters such as
///      `callbackGasLimit`, `condition`, and `ciphertext`.
/// @param callbackGasLimit The gas limit for the callback function to be executed after the blocklock request.
/// @param condition The condition for decryption of the Ciphertext encoded as bytes.
/// @param ciphertext The ciphertext to be used in the blocklock request.
/// @notice This function internally calls the `blocklock.requestBlocklock` function.
function _requestBlocklockPayInNative(
    uint32 callbackGasLimit,
    bytes condition,
    TypesLib.Ciphertext calldata ciphertext
) internal returns (uint256 requestId, uint256 requestPrice) {
    requestPrice = blocklock.calculateRequestPriceNative(callbackGasLimit);
    return
        (blocklock.requestBlocklock{value: requestPrice}(callbackGasLimit, condition, ciphertext), requestPrice);
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
///      `callbackGasLimit`, `subscriptionId`, `condition`, and `ciphertext`.
/// @param callbackGasLimit The gas limit for the callback function to be executed after the blocklock request.
/// @param condition The condition for decryption of the Ciphertext encoded as bytes.
/// @param ciphertext The ciphertext to be used in the blocklock request.
/// @return requestId The unique identifier for the blocklock request.
/// @notice This function internally calls the `blocklock.requestBlocklockWithSubscription` function.
function _requestBlocklockWithSubscription(
    uint32 callbackGasLimit,
    bytes condition,
    TypesLib.Ciphertext calldata ciphertext
) internal returns (uint256 requestId) {
    return blocklock.requestBlocklockWithSubscription(callbackGasLimit, subscriptionId, condition, ciphertext);
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
    }
```

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

#### 3. Deploy the `BlocklockReceiver` contract
Before deploying, please verify that your target network is listed in the Supported Networks section. All contracts that initiate requests must be initialized with the appropriate deployed **BlocklockSender (Proxy)** specific to their host network.

Example Foundry Script for Filecoin Calibration Testnet deployment: 
```solidity
address blocklockSenderProxy = 0xF8e2477647Ee6e33CaD4C915DaDc030b74AB976b;
MockBlocklockReceiver mockBlocklockReceiver = new MockBlocklockReceiver(address(blocklockSenderProxy));
console.log("\nMockBlocklockReceiver deployed at: ", address(mockBlocklockReceiver));
```

To view a full example, please check the following links:
- Example solidity contract for creating conditional encryption requests and receiving decryption keys via callbacks - [MockBlocklockReceiver.sol](./src/mocks/MockBlocklockReceiver.sol) 
- Example off-chain [data encoding and encryption](https://github.com/randa-mu/blocklock-js?tab=readme-ov-file#example-encrypting-a-uint256-4-eth-for-decryption-2-blocks-later).



#### How It Works

* Encryption: Use the off-chain TypeScript library ([blocklock-js](https://github.com/randa-mu/blocklock-js)) to generate the encrypted data (`TypesLib.Ciphertext`) with a threshold network public key. The following solidity types are supported by the TypeScript library - uint256, int256, address, string, bool, bytes32, bytes, uint256[], address[], and struct. An example can be found in the [blocklock-js](https://github.com/randa-mu/blocklock-js?tab=readme-ov-file#example-encrypting-a-uint256-4-eth-for-decryption-2-blocks-later) library.
* Conditional Encryption Request: Call the appropriate `requestBlocklock` function (depending on the request funding route as described above) with the callbackGasLimit, condition for decryption, and the encrypted data or Ciphertext.
* Decryption: After the specified condition has been met, a callback to your `receiveBlocklock` logic is triggered with the decryption key which can be used unlock the data in your smart contract.


## 📜 Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

## 🤝 Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

## 🎉 Acknowledgments

Special thanks to the Filecoin Foundation for supporting the development of this library.
