// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Constants} from "../libraries/Constants.sol";

import {JsonUtils} from "../utils/JsonUtils.sol";
import {EnvReader} from "../utils/EnvReader.sol";

import {BlocklockSender} from "src/blocklock/BlocklockSender.sol";
import {UUPSProxy} from "src/proxy/UUPSProxy.sol";
import {Factory} from "src/factory/Factory.sol";

/// @title DeployBlocklockSender
/// @author Randamu
/// @dev Script for deploying or upgrading the BlocklockSender contract.
/// Reads an environment variable to determine if it's an upgrade (new implementation only) or a full deployment.
contract DeployBlocklockSender is JsonUtils, EnvReader {
    /// @notice Runs the deployment script, checking the environment variable to determine whether to upgrade or deploy.
    function run() public virtual {
        bool isUpgrade = vm.envBool("IS_UPGRADE");
        address decryptionSenderProxyAddress =
            _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "decryptionSenderProxyAddress");
        deployBlocklockSenderProxy(decryptionSenderProxyAddress, isUpgrade);
    }

    /// @notice Deploys the BlocklockSender proxy contract or upgrades its implementation.
    /// @param decryptionSenderProxyAddress The address of the DecryptionSender proxy contract.
    /// @param isUpgrade A flag indicating whether to perform an upgrade (true) or a full deployment (false).
    function deployBlocklockSenderProxy(address decryptionSenderProxyAddress, bool isUpgrade)
        internal
        returns (BlocklockSender blocklockSenderInstance)
    {
        address implementation = deployBlocklockSenderImplementation();

        if (isUpgrade) {
            vm.broadcast();
            address proxyAddress =
                _readAddressFromJsonInput(Constants.DEPLOYMENT_INPUT_JSON_PATH, "blocklockSenderProxyAddress");

            BlocklockSender(proxyAddress).upgradeToAndCall(implementation, "");
            console.log("BlocklockSender contract upgraded to new implementation at: ", implementation);
            blocklockSenderInstance = BlocklockSender(proxyAddress);
        } else {
            // Deploy a new proxy if it's a full deployment
            bytes memory code = abi.encodePacked(type(UUPSProxy).creationCode, abi.encode(implementation, ""));

            vm.broadcast();
            address contractAddress;

            if (vm.envBool("USE_RANDAMU_FACTORY")) {
                contractAddress =
                    Factory(vm.envAddress("RANDAMU_CREATE2_FACTORY_CONTRACT_ADDRESS")).deploy(Constants.SALT, code);

                blocklockSenderInstance = BlocklockSender(contractAddress);
            } else {
                UUPSProxy proxy = new UUPSProxy{salt: Constants.SALT}(implementation, "");
                blocklockSenderInstance = BlocklockSender(address(proxy));

                contractAddress = address(proxy);
            }

            _writeAddressToJsonInput(
                Constants.DEPLOYMENT_INPUT_JSON_PATH, "blocklockSenderProxyAddress", contractAddress
            );

            vm.broadcast();
            blocklockSenderInstance.initialize(getSignerAddress(), decryptionSenderProxyAddress);

            console.log("BlocklockSender proxy contract deployed at: ", contractAddress);
        }

        setBlocklockSenderUserBillingConfiguration(
            uint32(vm.envUint("MAX_GAS_LIMIT")),
            uint32(vm.envUint("GAS_AFTER_PAYMENT_CALCULATION")),
            uint32(vm.envUint("FULFILLMENT_FLAT_FEE_NATIVE_PPM")),
            uint32(vm.envUint("WEI_PER_UNIT_GAS")),
            uint32(vm.envUint("BLS_PAIRING_CHECK_OVERHEAD")),
            uint8(vm.envUint("NATIVE_PREMIUM_PERCENTAGE")),
            uint16(vm.envUint("GAS_FOR_CALL_EXACT_CHECK")),
            blocklockSenderInstance
        );
    }

    /// @notice Deploys the BlocklockSender implementation contract.
    /// @return implementation The address of the newly deployed implementation contract.
    function deployBlocklockSenderImplementation() internal returns (address implementation) {
        bytes memory code = type(BlocklockSender).creationCode;

        vm.broadcast();
        if (vm.envBool("USE_RANDAMU_FACTORY")) {
            implementation =
                Factory(vm.envAddress("RANDAMU_CREATE2_FACTORY_CONTRACT_ADDRESS")).deploy(Constants.SALT, code);
        } else {
            BlocklockSender blocklockSender = new BlocklockSender{salt: Constants.SALT}();
            implementation = address(blocklockSender);
        }

        console.log("BlocklockSender implementation contract deployed at: ", implementation);
    }

    /**
     * @notice Sets the billing configuration for BlocklockSender.
     *         On Filecoin (chain IDs 314 and 314159), gas-related parameters are scaled by 500
     *         due to the difference in gas units compared to Ethereum.
     *         Reference: https://docs.filecoin.io/smart-contracts/filecoin-evm-runtime/difference-with-ethereum
     */
    function setBlocklockSenderUserBillingConfiguration(
        uint32 maxGasLimit,
        uint32 gasAfterPaymentCalculation,
        uint32 fulfillmentFlatFeeNativePPM,
        uint32 weiPerUnitGas,
        uint32 blsPairingCheckOverhead,
        uint8 nativePremiumPercentage,
        uint32 gasForCallExactCheck,
        BlocklockSender blocklockSender
    ) internal {
        uint256 chainId = getChainId();

        // If on Filecoin mainnet or calibration testnet, scale gas unit parameters
        if (chainId == 314 || chainId == 314159) {
            maxGasLimit *= 500;
            gasAfterPaymentCalculation *= 500;
            blsPairingCheckOverhead *= 500;
            gasForCallExactCheck *= 500;
        }

        vm.broadcast();
        blocklockSender.setConfig(
            maxGasLimit,
            gasAfterPaymentCalculation,
            fulfillmentFlatFeeNativePPM,
            weiPerUnitGas,
            blsPairingCheckOverhead,
            nativePremiumPercentage,
            gasForCallExactCheck
        );
    }

    function getChainId() internal view returns (uint256) {
        return block.chainid;
    }
}
