## blocklock-solidity

This repository provides an easy-to-use Solidity smart contract interface that facilitates Randamu's onchain conditional encryption.

By leveraging this library, developers can implement conditional data unlocking mechanisms securely in their smart contracts.

This library is designed with modularity and simplicity in mind, allowing developers to extend and integrate it into their existing projects easily.

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
| **BlocklockSender Proxy** | A lightweight proxy contract that enables upgradeability for the `BlocklockSender` implementation. It delegates all calls to the underlying implementation and serves as the primary interface for user interaction. | <br>- Filecoin Calibration Testnet: [0x366eAbCC6c26eC7De3b15d4129E4c89E52d9Cbc2](https://calibration.filfox.info/en/address/0x366eAbCC6c26eC7De3b15d4129E4c89E52d9Cbc2)<br> - Base Sepolia: [0xaeBc9Ebe8A5e5f6B6a326297BCbc64C5d3b2A9C3](https://sepolia.basescan.org/address/0xaeBc9Ebe8A5e5f6B6a326297BCbc64C5d3b2A9C3) <br> - Polygon PoS: [0xaeBc9Ebe8A5e5f6B6a326297BCbc64C5d3b2A9C3](https://polygonscan.com/address/0xaeBc9Ebe8A5e5f6B6a326297BCbc64C5d3b2A9C3) <br> | 
| BlocklockSender Implementation | Handles conditional encryption requests, callbacks, and fee collection. | <br>- Filecoin Calibration Testnet: [0xFF50398A5dBE717f398596746Ba5120Be00C18a5](https://calibration.filfox.info/en/address/0xFF50398A5dBE717f398596746Ba5120Be00C18a5)<br> - Base Sepolia: [0xB87fFcAF968f2ef0df60217E31cBcBa35bd89D80](https://sepolia.basescan.org/address/0xB87fFcAF968f2ef0df60217E31cBcBa35bd89D80) <br> - Polygon PoS: [0xB87fFcAF968f2ef0df60217E31cBcBa35bd89D80](https://polygonscan.com/address/0xB87fFcAF968f2ef0df60217E31cBcBa35bd89D80) | 
| DecryptionSender Proxy | Upgradeable proxy for DecryptionSender. | <br>- Filecoin Calibration Testnet:[0x0119eC9e9b56de1dcc1820FC69dF6f55Aa9AE081](https://calibration.filfox.info/en/address/0x0119eC9e9b56de1dcc1820FC69dF6f55Aa9AE081)<br> - Base Sepolia: [0xC41a11aBa6eEFfe6e230809a569c2130222D748c](https://sepolia.basescan.org/address/0xC41a11aBa6eEFfe6e230809a569c2130222D748c) <br> - Polygon PoS: [0xC41a11aBa6eEFfe6e230809a569c2130222D748c](https://polygonscan.com/address/0xC41a11aBa6eEFfe6e230809a569c2130222D748c)| 
| DecryptionSender Implementation | Contract used by offchain oracle to fulfill conditional encryption requests. | <br>- Filecoin Calibration Testnet: [0xb4718fAF28C3C6B5598CbBAD50a03A72D70f49F2](https://calibration.filfox.info/en/address/0xb4718fAF28C3C6B5598CbBAD50a03A72D70f49F2)<br> - Base Sepolia: [0xe21D194ac77194668E6d223461FFB5b2Ba7e399B](https://sepolia.basescan.org/address/0xe21D194ac77194668E6d223461FFB5b2Ba7e399B) <br> - Polygon PoS: [0xe21D194ac77194668E6d223461FFB5b2Ba7e399B](https://polygonscan.com/address/0xe21D194ac77194668E6d223461FFB5b2Ba7e399B) | 
| SignatureSchemeAddressProvider | Stores contract addresses for signature schemes. | <br>- Filecoin Calibration Testnet: [0x76a1C3628504c204c44e58E86eFbD3e9f054093f](https://calibration.filfox.info/en/address/0x76a1C3628504c204c44e58E86eFbD3e9f054093f)<br> - Base Sepolia: [0xb968B1f9dD8dfa742568EDb3d8659910C14B0C44](https://sepolia.basescan.org/address/0xb968B1f9dD8dfa742568EDb3d8659910C14B0C44) <br> - Polygon PoS: [0xb968B1f9dD8dfa742568EDb3d8659910C14B0C44](https://polygonscan.com/address/0xb968B1f9dD8dfa742568EDb3d8659910C14B0C44) | 
| BlocklockSignatureScheme | BN254 pairing-based signature verifier. | <br>- Filecoin Calibration Testnet: [0x09d76E4070fadc56135e772410795727CCA21e89](https://calibration.filfox.info/en/address/0x09d76E4070fadc56135e772410795727CCA21e89)<br> - Base Sepolia: [0x322c130D0b3A96D828c886C6eeb08Af55f63d4D1](https://sepolia.basescan.org/address/0x322c130D0b3A96D828c886C6eeb08Af55f63d4D1) <br> - Polygon PoS: [0x322c130D0b3A96D828c886C6eeb08Af55f63d4D1](https://polygonscan.com/address/0x322c130D0b3A96D828c886C6eeb08Af55f63d4D1) | 


### Using the Solidity Interface


#### Importing the Interface

To use this abstract contract in your project, the first step is to import the required files into your contract and use the proxy contract address for BlocklockSender in the constructor as the blocklockContract parameter:

```solidity
// Import the Types library for managing ciphertexts
import {TypesLib} from "blocklock-solidity/src/libraries/TypesLib.sol";
// Import the AbstractBlocklockReceiver for handling timelock decryption callbacks
import {AbstractBlocklockReceiver} from "blocklock-solidity/src/AbstractBlocklockReceiver.sol";
```

#### Example Usage

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {TypesLib} from "../libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";

/// @title MockBlocklockReceiver
/// @dev A mock implementation of a Blocklock receiver that interacts with the Blocklock contract
/// and receives decryption keys from Randamu's threshold network.
/// This contract stores encrypted values and decrypts them when the decryption key is received.
contract MockBlocklockReceiver is AbstractBlocklockReceiver {
    /// @notice Stores the request ID associated with the blocklock request.
    uint256 public requestId;

    /// @notice Stores the encrypted value associated with the blocklock request.
    TypesLib.Ciphertext public encryptedValue;

    /// @notice Stores the decrypted plaintext value after decryption.
    uint256 public plainTextValue;

    /// @dev Initializes the contract by setting the Blocklock contract address.
    /// @param blocklockContract The address of the Blocklock contract.
    constructor(address blocklockContract) AbstractBlocklockReceiver(blocklockContract) {}

    /// @notice Creates a conditional encryption request with the specified decryption chain height and encrypted data.
    /// @dev This function requests a conditional encryption by calling `requestBlocklock`, stores the encrypted data, and returns the request ID.
    /// @param decryptionChainHeight The chain height at which the encrypted data can be decrypted.
    /// @param encryptedData The encrypted data that needs to be securely stored until the decryption block is reached.
    /// @return requestId The ID of the created timelock request.
    function createTimelockRequest(uint256 decryptionBlockNumber, TypesLib.Ciphertext calldata encryptedData)
        external
        returns (uint256)
    {
        // create timelock request
        requestId = blocklock.requestBlocklock(decryptionBlockNumber, encryptedData);
        // store Ciphertext
        encryptedValue = encryptedData;
        return requestId;
    }

    /// @notice Handles the receipt of a decryption key linked to a conditional encryption
    /// request by verifying the request ID and decrypting the stored ciphertext.
    /// @dev This function is called when a conditional encryption condition is met
    /// e.g., chain height. 
    /// The function ensures the request ID matches and then decrypts the stored ciphertext using the provided decryption key.
    /// @param _requestId The ID of the request that needs to be verified.
    /// @param decryptionKey The decryption key used to decrypt the stored ciphertext.
    /// @return None This function does not return a value but updates the state variable `plainTextValue` with the decrypted result.
    function _onBlocklockReceived(uint256 _requestId, bytes calldata decryptionKey) internal override {
        require(requestId == _requestId, "Invalid request id.");
        // decrypt stored Ciphertext with decryption key
        plainTextValue = abi.decode(blocklock.decrypt(encryptedValue, decryptionKey), (uint256));
    }
}
```

#### How It Works

* Encryption: Use the off-chain TypeScript library ([blocklock-js](https://github.com/randa-mu/blocklock-js)) to generate the encrypted data (`TypesLib.Ciphertext`) with a threshold network public key. The following solidity types are supported by the TypeScript library - uint256, int256, address, string, bool, bytes32, bytes, uint256[], address[], and struct.
* Timelock Request: Call `requestBlocklock` with the chain height after which decryption is allowed and the encrypted data or Ciphertext.
* Decryption: Once the specified chain height is reached, a callback to your `receiveBlocklock` logic is triggered with the decryption key to unlock the data.

### Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

### Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

### Acknowledgments

Special thanks to the Filecoin Foundation for supporting the development of this library.
