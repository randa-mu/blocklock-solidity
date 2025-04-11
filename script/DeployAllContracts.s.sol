// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {Script} from "forge-std/Script.sol";

import {Constants} from "./libraries/Constants.sol";

import {BlocklockSender, DeployBlocklockSender} from "./single-deployment/DeployBlocklockSender.s.sol";
import {
    SignatureSchemeAddressProvider,
    DeploySignatureSchemeAddressProvider
} from "./single-deployment/DeploySignatureSchemeAddressProvider.s.sol";
import {
    BlocklockSignatureScheme,
    DeployBlocklockSignatureScheme
} from "./single-deployment/DeployBlocklockSignatureScheme.s.sol";
import {DecryptionSender, DeployDecryptionSender} from "./single-deployment/DeployDecryptionSender.s.sol";
import {MockBlocklockReceiver, DeployBlocklockReceiver} from "./single-deployment/DeployBlocklockReceiver.s.sol";

/// @title DeployAllContracts
/// @author Randamu
/// @notice A deployment contract that deploys all contracts required for
/// blocklock requests and randomness requests.
contract DeployAllContracts is
    DeployBlocklockSender,
    DeploySignatureSchemeAddressProvider,
    DeployBlocklockSignatureScheme,
    DeployDecryptionSender,
    DeployBlocklockReceiver
{
    function run()
        public
        override(
            DeployBlocklockSender,
            DeploySignatureSchemeAddressProvider,
            DeployBlocklockSignatureScheme,
            DeployDecryptionSender,
            DeployBlocklockReceiver
        )
    {
        deployAll();
    }

    /// @notice Deploys all required contracts or upgrades them based on the `isUpgrade` flag.
    /// @dev This function initializes multiple contracts and links them together as needed.
    /// @return mockBlocklockReceiver The deployed instance of MockBlocklockReceiver.
    /// @return blocklockSenderInstance The deployed instance of BlocklockSender.
    /// @return blocklockSignatureScheme The deployed instance of BlocklockSignatureScheme.
    /// @return decryptionSenderInstance The deployed instance of DecryptionSender.
    /// @return signatureSchemeAddressProvider The deployed instance of SignatureSchemeAddressProvider.
    function deployAll()
        public
        returns (
            MockBlocklockReceiver mockBlocklockReceiver,
            BlocklockSender blocklockSenderInstance,
            BlocklockSignatureScheme blocklockSignatureScheme,
            DecryptionSender decryptionSenderInstance,
            SignatureSchemeAddressProvider signatureSchemeAddressProvider
        )
    {
        // for upgrades, run deployment script for individual contract in single-deployments
        bool isUpgrade = false;
        // signature scheme address provider
        signatureSchemeAddressProvider = deploySignatureSchemeAddressProvider();
        // signature schemes
        blocklockSignatureScheme = deployBlocklockSignatureScheme();
        // decryption sender
        decryptionSenderInstance = deployDecryptionSenderProxy(address(signatureSchemeAddressProvider), isUpgrade);
        // blocklock sender
        blocklockSenderInstance = deployBlocklockSenderProxy(address(decryptionSenderInstance), isUpgrade);
        // mocks
        mockBlocklockReceiver = deployBlocklockReceiver(address(blocklockSenderInstance));
    }
}
