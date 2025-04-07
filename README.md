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


### Deployment

The deployment [scripts](script) enable the deployment of single contracts or all contracts in a single run.

#### Environment setup

Create a `.env` file. Then copy the `.env.example` to the `.env` file and set the applicable configuration variables for the testing / deployment environment.

#### Deploy the CREATE2 Factory Contract

Deploy the [CREATE2 Factory.sol](src/factory/Factory.sol) contract and set the `CREATE2_FACTORY` address in the [Constants.sol library](script/libraries/Constants.sol) used by the deployment scripts. Also set the address linked to the deployer private key as the `ADMIN` address in the same [Constants.sol library](script/libraries/Constants.sol) file. This address will be set as the default admin in the core contracts.

```sh
source .env

# Deploy CREATE2 Factory
forge script script/DeployFactory.s.sol:DeployFactory --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

For Filecoin Calibration Testnet, a common [deployment issue](https://github.com/filecoin-project/fevm-foundry-kit) that you may see is a failure due to gas. Simply pass in a higher gas limit to fix this (either via. a higher gas estimate multiplier using the `-g` flag or a fixed gas limit) e.g.,

```sh
forge script script/DeployFactory.s.sol:DeployFactory --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -g 10000
```

#### Deploy All Contracts

Deployment is handled by solidity scripts in forge. The network being deployed to is dependent on the `RPC_URL` environment variable.

To deploy all contracts in a single run, the `DeployAllContracts` script is used. This will run the deployments for all contracts specified in the script.
```sh
source .env

forge script script/DeployAllContracts.s.sol:DeployAllContracts --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

For Etherscan verification, ensure that the `ETHERSCAN_API_KEY` environment variable is set and add the `--verify` flag to the forge script deployment commands.


#### Deploy a Single Contract

To deploy a single contract, the scripts within the `script/single-deployment` directory are used, e.g., to deploy only the `BlocklockSignatureScheme.sol` contract contract, the command below is used:

```sh
source .env

forge script script/single-deployment/DeployBlocklockSignatureScheme.s.sol:DeployBlocklockSignatureScheme --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

To resolve dependencies between the contract deployments, a `.json` file named [Deployment_input.json](script/json/Deployment_input.json) in the [script](script) folder is filled with contract addresses for the following contracts after they are deployed (either as single deployments or part of the single run deployment for all contracts):
* BlocklockSender (proxy address)
* DecryptionSender (proxy address)
* SignatureSchemeAddressProvider

The addresses from this input file are read in by scripts using them. To overwrite the addresses in this file, replace them with the relevant address for each contract.

For example, running the following command writes a JSON property `{"signatureSchemeAddressProviderAddress": "0x7D020A4E3D8795581Ec06E0e57701dDCf7B19EDF"}` to the Deployment_input.json file:

```bash
forge script script/single-deployments/DeploySignatureSchemeAddressProvider.s.sol:DeploySignatureSchemeAddressProvider --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

Which is used by the [DeployBlocklockSignatureScheme.sol](script/single-deployments/DeployBlocklockSignatureScheme.s.sol) deployment script when deploying [BlocklockSignatureScheme.sol](src/signature-schemes/BlocklockSignatureScheme.sol).


#### Upgrade a Single Contract

To upgrade the impelementation contract for any of the `Sender` contracts, set the `IS_UPGRADE` to `true` in the `.env` file. Then in [Constants.sol](script/libraries/Constants.sol), increment the `SALT` for deployment. Then run the deployment command only for the specific contract to upgrade, e.g., if upgrading `DecryptionSender` implementation, run the following command for a single contract deployment:

```bash
forge script script/single-deployments/DeployDecryptionSender.s.sol:DeployDecryptionSender --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

#### Deployment addresses

The file `contract-addresses.json` lists all official deployments of the contracts in this repository by `chain id`.

The deployment addresses file is generated with:

```sh
bash utils/generate-contract-addresses.sh > contract-addresses.json
```


### Smart Contract Addresses

| Contract        | Address | Network          |
|-----------------|---------|------------------|
| BlocklockSender Proxy | 0xfF66908E1d7d23ff62791505b2eC120128918F44   | Filecoin Calibration Testnet |
| BlocklockSender Implementation | 0x02097463c21f21214499FAa538240029d2e4A220   | Filecoin Calibration Testnet |
| DecryptionSender Proxy | 0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3   | Filecoin Calibration Testnet |
| DecryptionSender Implementation | 0xea9111e44D23029945f2E46b2bFf26b04D15bd6F   | Filecoin Calibration Testnet |
| SignatureSchemeAddressProvider | 0xD2b5084E68230D609AEaAe5E4cF7df9ebDd6375A   | Filecoin Calibration Testnet |
| BlocklockSignatureScheme | 0x62C9CF8Ff30177d8479eDaB017f38017bEbf10C2   | Filecoin Calibration Testnet |
| MockBlocklockReceiver | 0x6f637EcB3Eaf8bEd0fc597Dc54F477a33BBCA72B   | Filecoin Calibration Testnet |


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
