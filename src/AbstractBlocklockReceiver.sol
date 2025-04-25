// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IBlocklockReceiver} from "./interfaces/IBlocklockReceiver.sol";
import {IBlocklockSender, TypesLib} from "./interfaces/IBlocklockSender.sol";

import {ConfirmedOwner} from "./access/ConfirmedOwner.sol";

/// @title AbstractBlocklockReceiver contract
/// @author Randamu
/// @notice Base contract which blocklock decryption key receiver contracts must implement
/// @notice to receive decryption keys via callbacks to the receiveBlocklock function.
abstract contract AbstractBlocklockReceiver is IBlocklockReceiver, ConfirmedOwner {
    /// @notice BlocklockSender contract for conditional encryption requests, subscription management and handling decryption keys
    IBlocklockSender public blocklock;

    /// @notice Event to log direct transfer of native tokens to the contract
    event Received(address, uint256);

    /// @notice Event to log deposits of native tokens
    event Funded(address indexed sender, uint256 amount);

    /// @notice Event to log withdrawals of native tokens
    event Withdrawn(address indexed recipient, uint256 amount);

    /// @notice Event logged when a new subscription id is set
    event NewSubscriptionId(uint256 indexed subscriptionId);

    /// @notice The subscription ID used for conditional encryption.
    /// @dev Used in interactions with IBlocklockSender for subscription management, e.g.,
    /// @dev funding and consumer contract address registration.
    uint256 public subscriptionId;

    /// @notice Ensures that the caller is the designated Blocklock contract.
    /// @dev This modifier restricts access to the function it modifies to only the Blocklock contract.
    ///      If the caller is not the Blocklock contract, the transaction will revert with an error message.
    /// @notice Reverts with the error message "Only blocklock contract can call" if the caller is not the Blocklock contract.
    modifier onlyBlocklockContract() {
        require(msg.sender == address(blocklock), "Only blocklock contract can call");
        _;
    }

    constructor(address blocklockSender) ConfirmedOwner(msg.sender) {
        blocklock = IBlocklockSender(blocklockSender);
    }

    /// @notice Receives a blocklock request and the associated decryption key.
    /// @dev This function is only callable by a contract that is recognized as a valid "BlocklockContract".
    ///      Once the decryption key is received, it triggers the internal function `_onBlocklockReceived` to handle the processing.
    /// @param requestID The unique identifier of the blocklock request.
    /// @param decryptionKey The decryption key that will be used to decrypt the associated ciphertext.
    /// @notice Emits an event or performs additional logic in `_onBlocklockReceived`.
    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey) external virtual onlyBlocklockContract {
        _onBlocklockReceived(requestID, decryptionKey);
    }

    /// @notice Sets the Randamu subscription ID used for conditional encryption oracle services.
    /// @dev Only callable by the contract owner.
    /// @param subId The new subscription ID to be set.
    function setSubId(uint256 subId) external onlyOwner {
        subscriptionId = subId;
        emit NewSubscriptionId(subId);
    }

    /// @notice Sets the address of the IBlocklockSender contract.
    /// @dev Only the contract owner can call this function.
    /// @param _blocklock The address of the deployed IBlocklockSender contract.
    function setBlocklock(address _blocklock) external onlyOwner {
        require(_blocklock != address(0), "Cannot set zero address as sender");
        blocklock = IBlocklockSender(_blocklock);
    }

    /// @notice Adds a list of consumer addresses to the Randamu subscription.
    /// @dev Requires the subscription ID to be set before calling.
    /// @param consumers An array of addresses to be added as authorized consumers.
    function updateSubscription(address[] calldata consumers) external onlyOwner {
        require(subscriptionId != 0, "subID not set");
        for (uint256 i = 0; i < consumers.length; i++) {
            blocklock.addConsumer(subscriptionId, consumers[i]);
        }
    }

    /// @notice Creates and funds a new Randamu subscription using native currency.
    /// @dev Only callable by the contract owner. If a subscription already exists, it will not be recreated.
    /// @dev The ETH value sent in the transaction (`msg.value`) will be used to fund the subscription.
    function createSubscriptionAndFundNative() external payable onlyOwner {
        subscriptionId = _subscribe();
        blocklock.fundSubscriptionWithNative{value: msg.value}(subscriptionId);
    }

    /// @notice Function to fund the contract with native tokens for direct funding requests.
    function fundContractNative() external payable {
        require(msg.value > 0, "You must send some ETH");
        emit Funded(msg.sender, msg.value);
    }

    /// @notice Function to withdraw native tokens from the contract.
    /// @dev Only callable by contract owner.
    /// @param amount The amount to withdraw.
    /// @param recipient The address to send the tokens to.
    function withdrawNative(uint256 amount, address recipient) external onlyOwner {
        require(getBalance() >= amount, "Insufficient funds in contract");
        payable(recipient).transfer(amount);
        emit Withdrawn(recipient, amount);
    }

    /// @notice Tops up the Randamu subscription using native currency (e.g., ETH).
    /// @dev Requires a valid subscription ID to be set before calling.
    /// @dev The amount to top up should be sent along with the transaction as `msg.value`.
    function topUpSubscriptionNative() external payable {
        require(subscriptionId != 0, "sub not set");
        blocklock.fundSubscriptionWithNative{value: msg.value}(subscriptionId);
    }

    /// @notice getBalance returns the native balance of the consumer contract.
    /// @notice For direct funding requests, the contract needs to hold native tokens to
    /// sufficient enough to cover the cost of the request.
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Requests a blocklock without a subscription and returns the request ID and request price.
    /// @dev This function calls the `requestBlocklock` function from the `blocklock` contract, passing the required parameters such as
    ///      `callbackGasLimit`, `blockHeight`, and `ciphertext`.
    /// @param callbackGasLimit The gas limit for the callback function to be executed after the blocklock request.
    /// @param condition The condition for decryption of the Ciphertext.
    /// The decryption key is sent back to the contract when the condition is met.
    /// @param ciphertext The ciphertext to be used in the blocklock request.
    /// @notice This function internally calls the `blocklock.requestBlocklock` function.
    function _requestBlocklockPayInNative(
        uint32 callbackGasLimit,
        bytes memory condition,
        TypesLib.Ciphertext calldata ciphertext
    ) internal returns (uint256 requestId, uint256 requestPrice) {
        requestPrice = blocklock.calculateRequestPriceNative(callbackGasLimit);
        return (blocklock.requestBlocklock{value: requestPrice}(callbackGasLimit, condition, ciphertext), requestPrice);
    }

    /// @notice Requests a blocklock with a subscription and returns the request ID.
    /// @dev This function calls the `requestBlocklockWithSubscription` function from the `blocklock` contract, passing the required parameters such as
    ///      `callbackGasLimit`, `subscriptionId`, `blockHeight`, and `ciphertext`.
    /// @param callbackGasLimit The gas limit for the callback function to be executed after the blocklock request.
    /// @param condition The condition for decryption of the Ciphertext.
    /// The decryption key is sent back to the contract when the condition is met.
    /// @param ciphertext The ciphertext to be used in the blocklock request.
    /// @return requestId The unique identifier for the blocklock request.
    /// @notice This function internally calls the `blocklock.requestBlocklockWithSubscription` function.
    function _requestBlocklockWithSubscription(
        uint32 callbackGasLimit,
        bytes memory condition,
        TypesLib.Ciphertext calldata ciphertext
    ) internal returns (uint256 requestId) {
        return blocklock.requestBlocklockWithSubscription(callbackGasLimit, subscriptionId, condition, ciphertext);
    }

    /// @notice Decrypts the provided ciphertext using the specified decryption key.
    /// @dev This function calls the `decrypt` function from the `blocklock` contract to perform the decryption operation.
    ///      It requires that the `blocklock` contract implements decryption logic using the provided ciphertext and decryption key.
    /// @param ciphertext The ciphertext that needs to be decrypted.
    /// @param decryptionKey The decryption key to be used for decrypting the ciphertext.
    /// @return The decrypted plaintext as a `bytes` array.
    /// @notice This function internally calls the `blocklock.decrypt` function to perform the decryption.
    function _decrypt(TypesLib.Ciphertext memory ciphertext, bytes calldata decryptionKey)
        internal
        view
        returns (bytes memory)
    {
        return blocklock.decrypt(ciphertext, decryptionKey);
    }

    /// @notice Handles the reception of a blocklock with the provided decryption key.
    /// @dev This function is meant to be overridden in derived contracts to define the specific logic
    ///      for processing a blocklock upon receipt of a decryption key.
    /// @param _requestId The unique identifier of the blocklock request.
    /// @param decryptionKey The decryption key that corresponds to the ciphertext in the blocklock request.
    /// @notice This function does not implement any functionality itself but serves as a placeholder for derived contracts
    ///         to implement their specific logic when a blocklock is received.
    /// @dev This function is marked as `internal` and `virtual`, meaning it can be overridden in a derived contract.
    function _onBlocklockReceived(uint256 _requestId, bytes calldata decryptionKey) internal virtual;

    /// @notice Creates a new Randamu subscription if none exists and registers this contract as a consumer.
    /// @dev Internal helper that initializes the subscription only once.
    /// @return subId The subscription ID that was created or already exists.
    function _subscribe() internal returns (uint256 subId) {
        require(subscriptionId == 0, "SubscriptionId is not zero");
        subId = blocklock.createSubscription();
        blocklock.addConsumer(subId, address(this));
    }

    /// @notice Cancels an existing Randamu subscription if one exists.
    /// @dev Internal helper that cancels the subscription.
    /// @param to The recipient addresss that will receive the subscription balance.
    function _cancelSubscription(address to) internal {
        require(subscriptionId != 0, "SubscriptionId is zero");
        blocklock.cancelSubscription(subscriptionId, to);
    }

    /// @notice The receive function is executed on a call to the contract with empty calldata.
    /// This is the function that is executed on plain Ether transfers (e.g. via .send() or .transfer()).
    receive() external payable {
        emit Received(msg.sender, msg.value);
    }
}
