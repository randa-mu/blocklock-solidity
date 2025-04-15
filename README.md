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

#### Filecoin Calibration Testnet

| Contract        |  Description | Address | 
|-----------------|---------|---------|
| **BlocklockSender Proxy** | A lightweight and efficient proxy contract used in managing the upgradeablility of the BlocklockSender implementation contract and delegates calls to the implementation contract. This is the contract users will interact with. | [0xfF66908E1d7d23ff62791505b2eC120128918F44](https://calibration.filfox.info/en/address/0xfF66908E1d7d23ff62791505b2eC120128918F44) | 
| BlocklockSender Implementation | Implementation contract which handles conditional encryption requests, delivers the decryption keys via callbacks to the requesting contract, and handles fee collection. | [0x02097463c21f21214499FAa538240029d2e4A220](https://calibration.filfox.info/en/address/0x02097463c21f21214499FAa538240029d2e4A220)   | 
| DecryptionSender Proxy | Proxy contract used to manage the upgradeability of the DecryptionSender implementation contract and delegates calls to the implementation contract. | [0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3](https://calibration.filfox.info/en/address/0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3)   | 
| DecryptionSender Implementation | Contract used by offchain oracle to fulfill conditional encryption requests. | [0xea9111e44D23029945f2E46b2bFf26b04D15bd6F](https://calibration.filfox.info/en/address/0xea9111e44D23029945f2E46b2bFf26b04D15bd6F)   | 
| SignatureSchemeAddressProvider | Manages the contract addresses for different signature schemes. | [0xD2b5084E68230D609AEaAe5E4cF7df9ebDd6375A](https://calibration.filfox.info/en/address/0xD2b5084E68230D609AEaAe5E4cF7df9ebDd6375A)   | 
| BlocklockSignatureScheme | The BN254 signature scheme contract. Contains signature verification logic using pairing checks. | [0x62C9CF8Ff30177d8479eDaB017f38017bEbf10C2](https://calibration.filfox.info/en/address/0x62C9CF8Ff30177d8479eDaB017f38017bEbf10C2)   | 


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
        encrytpedValue = encryptedData;
        return requestId;
    }

    /// @notice Handles the receipt of a decryption key linked to a conditional encryption
    /// request by verifying the request ID and decrypting the stored ciphertext.
    /// @dev This function is called when a conditional encryption condition is met
    /// e.g., chain height. 
    /// The function ensures the request ID matches and then decrypts the stored ciphertext using the provided decryption key.
    /// @param requestID The ID of the request that needs to be verified.
    /// @param decryptionKey The decryption key used to decrypt the stored ciphertext.
    /// @return None This function does not return a value but updates the state variable `plainTextValue` with the decrypted result.
    function _onBlocklockReceived(uint256 requestID, bytes calldata decryptionKey) internal override {
        require(requestID == requestId, "Invalid request id.");
        // decrypt stored Ciphertext with decryption key
        plainTextValue = abi.decode(blocklock.decrypt(encrytpedValue, decryptionKey), (uint256));
    }
}
```

#### How It Works

* Encryption: Use the off-chain TypeScript library ([blocklock-js](https://github.com/randa-mu/blocklock-js)) to generate the encrypted data (`TypesLib.Ciphertext`) with a threshold network public key. The following solidity types are supported by the TypeScript library - uint256, int256, address, string, bool, bytes32, bytes, uint256 array, address array, and struct.
* Timelock Request: Call `requestBlocklock` with the chain height after which decryption is allowed and the encrypted data or Ciphertext.
* Decryption: Once the specified chain height is reached, a callback to your `receiveBlocklock` logic is triggered with the decryption key to unlock the data.

### Licensing

This library is licensed under the MIT License which can be accessed [here](LICENSE).

### Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, feel free to open an issue or submit a pull request.

### Acknowledgments

Special thanks to the Filecoin Foundation for supporting the development of this library.
