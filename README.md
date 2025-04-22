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
| **BlocklockSender Proxy** | A lightweight proxy contract that enables upgradeability for the `BlocklockSender` implementation. It delegates all calls to the underlying implementation and serves as the primary interface for user interaction. | <br>- Filecoin Calibration Testnet: [0x366eAbCC6c26eC7De3b15d4129E4c89E52d9Cbc2](https://calibration.filfox.info/en/address/0x366eAbCC6c26eC7De3b15d4129E4c89E52d9Cbc2)<br> - Base Sepolia: [0x57B94510bC1D46DAd37ed2Bb9584Adc5c6F8A409](https://sepolia.basescan.org/address/0x57B94510bC1D46DAd37ed2Bb9584Adc5c6F8A409) <br> - Polygon PoS: [0x57B94510bC1D46DAd37ed2Bb9584Adc5c6F8A409](https://polygonscan.com/address/0x57B94510bC1D46DAd37ed2Bb9584Adc5c6F8A409) <br> | 
| BlocklockSender Implementation | Handles conditional encryption requests, callbacks, and fee collection. | <br>- Filecoin Calibration Testnet: [0xFF50398A5dBE717f398596746Ba5120Be00C18a5](https://calibration.filfox.info/en/address/0xFF50398A5dBE717f398596746Ba5120Be00C18a5)<br> - Base Sepolia: [0x864831323f8b93CcDe122651064bd43c9f0Deb46](https://sepolia.basescan.org/address/0x864831323f8b93CcDe122651064bd43c9f0Deb46) <br> - Polygon PoS: [0x864831323f8b93CcDe122651064bd43c9f0Deb46](https://polygonscan.com/address/0x864831323f8b93CcDe122651064bd43c9f0Deb46) | 
| DecryptionSender Proxy | Upgradeable proxy for DecryptionSender. | <br>- Filecoin Calibration Testnet:[0x0119eC9e9b56de1dcc1820FC69dF6f55Aa9AE081](https://calibration.filfox.info/en/address/0x0119eC9e9b56de1dcc1820FC69dF6f55Aa9AE081)<br> - Base Sepolia: [0x29E64A7083Cf1323c927B533E72Ab6ff9684a518](https://sepolia.basescan.org/address/0x29E64A7083Cf1323c927B533E72Ab6ff9684a518) <br> - Polygon PoS: [0x29E64A7083Cf1323c927B533E72Ab6ff9684a518](https://polygonscan.com/address/0x29E64A7083Cf1323c927B533E72Ab6ff9684a518)| 
| DecryptionSender Implementation | Contract used by offchain oracle to fulfill conditional encryption requests. | <br>- Filecoin Calibration Testnet: [0xb4718fAF28C3C6B5598CbBAD50a03A72D70f49F2](https://calibration.filfox.info/en/address/0xb4718fAF28C3C6B5598CbBAD50a03A72D70f49F2)<br> - Base Sepolia: [0x1a6dFDc9212dCB5b5Def950653CEC2cbdf474647](https://sepolia.basescan.org/address/0x1a6dFDc9212dCB5b5Def950653CEC2cbdf474647) <br> - Polygon PoS: [0x1a6dFDc9212dCB5b5Def950653CEC2cbdf474647](https://polygonscan.com/address/0x1a6dFDc9212dCB5b5Def950653CEC2cbdf474647) | 
| SignatureSchemeAddressProvider | Stores contract addresses for signature schemes. | <br>- Filecoin Calibration Testnet: [0x76a1C3628504c204c44e58E86eFbD3e9f054093f](https://calibration.filfox.info/en/address/0x76a1C3628504c204c44e58E86eFbD3e9f054093f)<br> - Base Sepolia: [0xD0eD0d8A531c118eDA0eb3212565E205452508e2](https://sepolia.basescan.org/address/0xD0eD0d8A531c118eDA0eb3212565E205452508e2) <br> - Polygon PoS: [0xD0eD0d8A531c118eDA0eb3212565E205452508e2](https://polygonscan.com/address/0xD0eD0d8A531c118eDA0eb3212565E205452508e2) | 
| BlocklockSignatureScheme | BN254 pairing-based signature verifier. | <br>- Filecoin Calibration Testnet: [0x09d76E4070fadc56135e772410795727CCA21e89](https://calibration.filfox.info/en/address/0x09d76E4070fadc56135e772410795727CCA21e89)<br> - Base Sepolia: [0x5071D4ddbb16C122166dd779F90eb8db4832A512](https://sepolia.basescan.org/address/0x5071D4ddbb16C122166dd779F90eb8db4832A512) <br> - Polygon PoS: [0x5071D4ddbb16C122166dd779F90eb8db4832A512](https://polygonscan.com/address/0x5071D4ddbb16C122166dd779F90eb8db4832A512) | 


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

An example decryption key `receiver` contract [MockBlocklockReceiver.sol](src/mocks/MockBlocklockReceiver.sol) has been provided in the `src/mocks` folder. It inherits from the [AbstractBlocklockReceiver](src/AbstractBlocklockReceiver.sol) base contract.

The contract makes conditional encryption requests for an `uint256` value.

Requests can be funded in two ways: 
1. Direct funding
2. Subscription account


##### Direct Funding 

The following internal function allows the smart contract to make requests without an active subscription. 

```solidity
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
    }
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
