## @randamu/blocklock-solidity

This repository contains the Solidity-based smart contracts library that facilitates Randamu's on-chain timelock encryption and decryption.

By leveraging this library, developers can implement time-based data unlocking mechanisms securely in their smart contracts.

This library is designed with modularity and simplicity in mind, allowing developers to extend and integrate it into their existing projects easily.

### Features
* Timelock Encryption: Encrypt data that can only be decrypted after a specified block number.
* Decryption Callback: Implement custom logic that gets triggered when the decryption key is received, i.e., decryption of the Ciphertext.
* Abstract Interface: Extend and implement the library to suit your specific needs.



### Smart Contract Addresses

| Contract        | Address | Network          |
|-----------------|---------|------------------|
| BlocklockSender Proxy | 0xc45580aE3e062aa154CA205A2B5f930194084C6A   | Filecoin Testnet |
| BlocklockSender Implementation | 0x8BBd8e486918160A082F6ae019233692553F645b   | Filecoin Testnet |
| DecryptionSender Proxy | 0xd78A7fBAdA3ba77EC5357Aabd4b66C6822cD3c6f   | Filecoin Testnet |
| DecryptionSender Implementation | 0xb92eB4524047ADa37D364b408e7CB061ceece409   | Filecoin Testnet |


### Using the Solidity Interfaces

To use this library in your project, import the required files into your contract and use the proxy contract address for BlocklockSender in the constructor as the blocklockContract parameter:

```solidity
// Import the Types library for managing ciphertexts
import {TypesLib} from "../libraries/TypesLib.sol";
// Import the AbstractBlocklockReceiver for handling timelock decryption callbacks
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";
```

#### Example Usage

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TypesLib} from "../libraries/TypesLib.sol";
import {AbstractBlocklockReceiver} from "../AbstractBlocklockReceiver.sol";

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
