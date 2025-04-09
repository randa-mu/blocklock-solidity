// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {IBlocklockReceiver} from "./interfaces/IBlocklockReceiver.sol";
import {IBlocklockSender, TypesLib} from "./interfaces/IBlocklockSender.sol";

import {ConfirmedOwner} from "./access/ConfirmedOwner.sol";

abstract contract AbstractBlocklockReceiver is IBlocklockReceiver, ConfirmedOwner {
    IBlocklockSender public blocklock;

    // Event to log deposits and withdrawals of native tokens
    event Funded(address indexed sender, uint256 amount);
    event Withdrawn(address indexed recipient, uint256 amount);

    /// @notice The Randamu subscription ID used for conditional encryption.
    /// @dev Used in interactions with IBlocklockSender for subscription management, e.g.,
    /// @dev funding and consumer contract address registration.
    uint256 public subscriptionId;

    modifier onlyBlocklockContract() {
        require(msg.sender == address(blocklock), "Only timelock contract can call this.");
        _;
    }

    constructor(address blocklockSender) ConfirmedOwner(msg.sender) {
        blocklock = IBlocklockSender(blocklockSender);
    }

    function _requestBlocklock(uint32 callbackGasLimit, uint256 blockHeight, TypesLib.Ciphertext calldata ciphertext)
        internal
        returns (uint256 requestID)
    {
        requestID = blocklock.requestBlocklock(callbackGasLimit, subscriptionId, blockHeight, ciphertext);
    }

    function receiveBlocklock(uint256 requestID, bytes calldata decryptionKey) external virtual onlyBlocklockContract {
        _onBlocklockReceived(requestID, decryptionKey);
    }

    function decrypt(TypesLib.Ciphertext memory ciphertext, bytes calldata decryptionKey)
        internal
        view
        returns (bytes memory)
    {
        return blocklock.decrypt(ciphertext, decryptionKey);
    }

    function _onBlocklockReceived(uint256 requestID, bytes calldata decryptionKey) internal virtual;

    /// @notice Sets the Randamu subscription ID used for conitional encryption oracle services.
    /// @dev Only callable by the contract owner.
    /// @param subId The new subscription ID to be set.
    function setSubId(uint256 subId) external onlyOwner {
        subscriptionId = subId;
    }

    /// @notice Sets the address of the IBlocklockSender contract.
    /// @dev Only the contract owner can call this function.
    /// @param _blocklockSender The address of the deployed sender contract.
    function setBlocklockSender(address _blocklockSender) external onlyOwner {
        require(_blocklockSender != address(0), "Cannot set zero address as sender");
        blocklock = IBlocklockSender(_blocklockSender);
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

    /// @notice Creates a new Randamu subscription if none exists and registers this contract as a consumer.
    /// @dev Internal helper that initializes the subscription only once.
    /// @return The subscription ID that was created or already exists.
    function _subscribe() internal returns (uint256) {
        if (subscriptionId == 0) {
            subscriptionId = blocklock.createSubscription();
            blocklock.addConsumer(subscriptionId, address(this));
        }
        return subscriptionId;
    }

    /// @notice Creates and funds a new Randamu subscription using native currency.
    /// @dev Only callable by the contract owner. If a subscription already exists, it will not be recreated.
    /// @dev The ETH value sent in the transaction (`msg.value`) will be used to fund the subscription.
    function createSubscriptionAndFundNative() external payable onlyOwner {
        _subscribe();
        blocklock.fundSubscriptionWithNative{value: msg.value}(subscriptionId);
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

    /// @notice Function to fund the contract with native tokens for direct funding requests.
    function fund() external payable {
        require(msg.value > 0, "You must send some ETH");
        emit Funded(msg.sender, msg.value);
    }

    /// @notice Function to withdraw native tokens from the contract.
    /// @dev Only callable by contract owner.
    /// @param amount The amount to withdraw.
    /// @param recipient The address to send the tokens to.
    function withdraw(uint256 amount, address recipient) external onlyOwner {
        require(getBalance() >= amount, "Insufficient funds in contract");
        payable(recipient).transfer(amount);
        emit Withdrawn(recipient, amount);
    }
}
