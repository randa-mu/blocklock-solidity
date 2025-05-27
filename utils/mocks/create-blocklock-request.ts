import { JsonRpcProvider, ethers, getBytes, AddressLike, AbiCoder, ParamType } from "ethers";
import 'dotenv/config'
import {
    DecryptionSender__factory,
    BlocklockSender__factory,
    MockBlocklockReceiver__factory
} from "../../typechain-types";
import { TypesLib as BlocklockTypes } from "../../typechain-types/src/blocklock/BlocklockSender";
import {
    IbeOpts,
    encrypt_towards_identity_g1,
    Ciphertext,
} from "../../utils/crypto/ibe-bn254";
import { keccak_256 } from "@noble/hashes/sha3";

// Usage:
// yarn ts-node utils/mocks/create-blocklock-request.ts 

const RPC_URL = process.env.RPC_URL;

// // polygon mainnet addresses
// const blocklockSenderAddr = "0x82Fed730CbdeC5A2D8724F2e3b316a70A565e27e"
// const decryptionSenderAddr = "0x41cF74811B6B326bAe4AC4Df5b829035CB8a05DA";
// const mockBlocklockReceiverAddr = "0x5F8C824A150170B325ec804d8163364926B9FF76";

// filecoin testnet addresses
const blocklockSenderAddr = "0xF00aB3B64c81b6Ce51f8220EB2bFaa2D469cf702"
const decryptionSenderAddr = "0x2474d71AB97F1189D0E0cc1b6EbF8118DCa83000";
const mockBlocklockReceiverAddr = "0xC23BDcc5b79718B9C2e48A37D3b30a96D3231D52";

// mockBlocklockReceiverAddr can be deployed with the following command:
// forge script script/single-deployment/DeployBlocklockReceiver.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -g 100000
// For Filecoin calibration testnet, ensure that blocklockSenderProxyAddress is set in script/json/Deployment_input.json
// {
//     "blocklockSenderProxyAddress": "0xF00aB3B64c81b6Ce51f8220EB2bFaa2D469cf702"
//   }
// and RANDAMU_CREATE2_FACTORY_CONTRACT_ADDRESS is set to filecoin calibration 
// testnet factory 0x93B465392F8B4993Db724690A3b527Ec035d3a9F in .env file alongside RPC_URL and PRIVATE_KEY and
// USE_RANDAMU_FACTORY set to true in .env file
// const mockBlocklockReceiverAddr = "0x228Be38159Fc2A30A98acfD2Eddc46E1afa67fdc";

// Create a provider using the RPC URL
const provider = new ethers.JsonRpcProvider(RPC_URL);

// Create a signer using the private key
const signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

async function getWalletBalance(walletAddress: string): Promise<void> {
    try {
        // Get the wallet balance
        const balance = await provider.getBalance(walletAddress);

        // Convert the balance from Wei to Ether and print it
        console.log(`Balance of ${walletAddress}: ${ethers.formatEther(balance)} ETH`);
    } catch (error) {
        console.error("Error fetching wallet balance:", error);
    }
}

async function latestBlockNumber(provider: JsonRpcProvider) {
    // Fetch the latest block number
    const latestBlockNumber = await provider.getBlockNumber();
    console.log(`Latest Block Number: ${latestBlockNumber}`);
    return latestBlockNumber;
}

async function createBlocklockRequest() {
    const decryptionSenderInstance = DecryptionSender__factory.connect(
        decryptionSenderAddr,
        signer,
    );

    const blocklockSenderInstance = BlocklockSender__factory.connect(
        blocklockSenderAddr,
        signer,
    );

    const mockBlocklockReceiverInstance = MockBlocklockReceiver__factory.connect(
        mockBlocklockReceiverAddr,
        signer,
    );

    const blockHeight = BigInt((await provider.getBlockNumber()) + 5);
    console.log("block height", blockHeight);

    // condition bytes
    const encodedCondition = encodeCondition(blockHeight);
    console.log("encoded condition", encodedCondition.toString());

    // identity for IBE
    // encrypt_towards_identity_g1 expects a uint8Array as input for the identity
    const identity = getBytes(encodedCondition);

    // message bytes
    const msg = ethers.parseEther("3"); // BigInt for 3 ETH
    const msgBytes = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);

    // generate Ciphertext
    const blocklock_default_pk = {
        x: {
            c0: BigInt("0x2691d39ecc380bfa873911a0b848c77556ee948fb8ab649137d3d3e78153f6ca"),
            c1: BigInt("0x2863e20a5125b098108a5061b31f405e16a069e9ebff60022f57f4c4fd0237bf"),
        },
        y: {
            c0: BigInt("0x193513dbe180d700b189c529754f650b7b7882122c8a1e242a938d23ea9f765c"),
            c1: BigInt("0x11c939ea560caf31f552c9c4879b15865d38ba1dfb0f7a7d2ac46a4f0cae25ba"),
        },
    };

    const network = await provider!.getNetwork();
    const chainId = network.chainId;

    const BLOCKLOCK_IBE_OPTS: IbeOpts = createBlocklockIbeOpts(chainId);

    const ct = encrypt_towards_identity_g1(encodedMessage, identity, blocklock_default_pk, BLOCKLOCK_IBE_OPTS);

    // compute gas price

    const feeData = await provider!.getFeeData();

    // feeData.gasPrice: Legacy flat gas price (used on non-EIP-1559 chains like Filecoin or older EVMs)
    const gasPrice = feeData.gasPrice!;

    // feeData.maxFeePerGas: Max total gas price we're willing to pay (base + priority), used in EIP-1559
    const maxFeePerGas = feeData.maxFeePerGas!;

    // feeData.maxPriorityFeePerGas: Tip to incentivize validators (goes directly to them)
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!;

    const isFilecoin = Number(chainId) === 314 || Number(chainId) === 314159;

    let callbackGasLimit = 5000000n;

    let txGasPrice: bigint;
    let filecoinllbackGasLimitBuffer = 400n;
    if (isFilecoin) {
        // Use legacy gasPrice directly
        txGasPrice = gasPrice > 0 ? gasPrice * 10n : (maxFeePerGas + maxPriorityFeePerGas) * 10n;
        callbackGasLimit = callbackGasLimit * filecoinllbackGasLimitBuffer;
    } else {
        // Use effective gas price based on EIP-1559
        txGasPrice = maxFeePerGas + maxPriorityFeePerGas;
        callbackGasLimit = callbackGasLimit;
    }

    // make direct funding request with enough callbackGasLimit to cover BLS operations in call to decrypt() function
    // in receiver contract and msg.value to cover the request price + a buffer

    const requestPrice = await blocklockSenderInstance.estimateRequestPriceNative(
        callbackGasLimit,
        txGasPrice
    );

    const bufferPercent = isFilecoin ? 300n : 10n;
    const valueToSend = requestPrice + (requestPrice * bufferPercent) / 100n;

    console.log("Native / ETH to pay for request", ethers.formatEther(valueToSend));

    const estimatedGas = await mockBlocklockReceiverInstance.createTimelockRequestWithDirectFunding.estimateGas(callbackGasLimit, encodedCondition, encodeCiphertextToSolidity(ct),
        {
            value: valueToSend, maxFeePerGas,
            maxPriorityFeePerGas,
        });
    console.log("estimated gas", estimatedGas);

    const tx = await mockBlocklockReceiverInstance
        .connect(signer)
        .createTimelockRequestWithDirectFunding(callbackGasLimit, encodedCondition, encodeCiphertextToSolidity(ct),
            {
                value: valueToSend, gasLimit: estimatedGas,
                maxFeePerGas,
                maxPriorityFeePerGas,
            });

    let receipt = await tx.wait(1);
    if (!receipt) {
        throw new Error("transaction has not been mined");
    }

    const reqId = await mockBlocklockReceiverInstance.requestId();
    console.log("Created request id:", reqId);

    console.log("Request tx created at block height:", await provider.getBlockNumber())
    console.log("is created blocklock request id inFlight in decryptionSender?:", await decryptionSenderInstance.isInFlight(reqId));
    console.log("is created blocklock request id inFlight in blocklockSender?:", await blocklockSenderInstance.isInFlight(reqId));
}

function encodeCiphertextToSolidity(ciphertext: Ciphertext): BlocklockTypes.CiphertextStruct {
    const u: { x: [bigint, bigint]; y: [bigint, bigint] } = {
        x: [ciphertext.U.x.c0, ciphertext.U.x.c1],
        y: [ciphertext.U.y.c0, ciphertext.U.y.c1],
    };

    return {
        u,
        v: ciphertext.V,
        w: ciphertext.W,
    };
}

async function replacePendingTransaction() {
    let txData = {
        to: "0x5d84b82b750B996BFC1FA7985D90Ae8Fbe773364",
        value: "0",
        chainId: 314159,
        nonce: 1420,
        gasLimit: 10000000000,
        gasPrice: 2000000000
    }
    let estimate = await provider.estimateGas(txData)
    txData.gasLimit = Number(estimate);
    txData.gasPrice = Number(ethers.parseUnits("0.14085197", "gwei"));
    let tx = await signer.sendTransaction(txData)
    let receipt = await tx.wait(1)
    console.log(receipt)
}

async function getTransactionCount(walletAddr: AddressLike) {
    const txCount = await provider.getTransactionCount(walletAddr);
    console.log(`Transaction count for ${walletAddr} is ${txCount}`);
    return txCount;
}

function encodeCondition(blockHeight: bigint): Uint8Array {
    const blockHeightBytes = getBytes(encodeParams(["uint256"], [blockHeight]))
    // 0x42 is the magic 'B' tag for the `blockHeight` condition
    return new Uint8Array([0x42, ...blockHeightBytes])
}

const createBlocklockIbeOpts = (chainId: bigint): IbeOpts => ({
    hash: keccak_256,
    k: 128,
    expand_fn: "xmd",
    dsts: {
        H1_G1: Buffer.from(`BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_${encodeParams(["uint256"], [chainId])}_`),
        H2: Buffer.from(`BLOCKLOCK_BN254_XMD:KECCAK-256_H2_${encodeParams(["uint256"], [chainId])}_`),
        H3: Buffer.from(`BLOCKLOCK_BN254_XMD:KECCAK-256_H3_${encodeParams(["uint256"], [chainId])}_`),
        H4: Buffer.from(`BLOCKLOCK_BN254_XMD:KECCAK-256_H4_${encodeParams(["uint256"], [chainId])}_`),
    },
})

const encodeParams = (dataTypes: readonly ParamType[] | readonly string[], data: readonly any[]): string => {
    const abiCoder = AbiCoder.defaultAbiCoder()
    return abiCoder.encode(dataTypes, data)
}

async function main() {
    const walletAddr = await signer.getAddress()

    try {
        // Get latest block number
        await latestBlockNumber(provider);

        // Get wallet ETH balance
        await getWalletBalance(walletAddr);

        // get signer wallet trasaction count
        await getTransactionCount(walletAddr);

        // create a new randomness request
        await createBlocklockRequest();
    } catch (error) {
        console.error("Error fetching latest block number:", error);
    }
}


main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error(err);
        process.exit(1);
    });