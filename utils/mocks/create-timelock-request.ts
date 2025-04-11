import { JsonRpcProvider, ethers, AbiCoder, getBytes, AddressLike } from "ethers";
import 'dotenv/config';
import {
    DecryptionSender__factory,
    BlocklockSender__factory,
    MockBlocklockReceiver__factory,
} from "../../typechain-types";
import { encrypt_towards_identity_g1, Ciphertext } from "../crypto";
import { TypesLib as BlocklockTypes } from "../../typechain-types/src/blocklock/BlocklockSender";
import { IbeOpts } from "../crypto";
import { keccak_256 } from "@noble/hashes/sha3";

// Constants
const RPC_URL = process.env.CALIBRATIONNET_RPC_URL;
const BLOCKLOCK_DEFAULT_PUBLIC_KEY = {
    x: {
        c0: BigInt("0x2691d39ecc380bfa873911a0b848c77556ee948fb8ab649137d3d3e78153f6ca"),
        c1: BigInt("0x2863e20a5125b098108a5061b31f405e16a069e9ebff60022f57f4c4fd0237bf"),
    },
    y: {
        c0: BigInt("0x193513dbe180d700b189c529754f650b7b7882122c8a1e242a938d23ea9f765c"),
        c1: BigInt("0x11c939ea560caf31f552c9c4879b15865d38ba1dfb0f7a7d2ac46a4f0cae25ba"),
    },
};

const BLOCKLOCK_IBE_OPTS: IbeOpts = {
    hash: keccak_256,
    k: 128,
    expand_fn: "xmd",
    dsts: {
        H1_G1: Buffer.from("BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_"),
        H2: Buffer.from("BLOCKLOCK_BN254_XMD:KECCAK-256_H2_"),
        H3: Buffer.from("BLOCKLOCK_BN254_XMD:KECCAK-256_H3_"),
        H4: Buffer.from("BLOCKLOCK_BN254_XMD:KECCAK-256_H4_"),
    },
};

// Contract Addresses
const blocklockSenderAddr = "0xfF66908E1d7d23ff62791505b2eC120128918F44";
const decryptionSenderAddr = "0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3";
const mockBlocklockReceiverAddr = "0x6f637EcB3Eaf8bEd0fc597Dc54F477a33BBCA72B";

// Setup provider and signer
const provider = new ethers.JsonRpcProvider(RPC_URL);
const signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

// Utility Functions

function encodeCiphertextToSolidity(ciphertext: Ciphertext): BlocklockTypes.CiphertextStruct {
    const u = { x: [ciphertext.U.x.c0, ciphertext.U.x.c1], y: [ciphertext.U.y.c0, ciphertext.U.y.c1] };
    return { u, v: ciphertext.V, w: ciphertext.W };
}

// Convert block height to big-endian bytes
function blockHeightToBEBytes(blockHeight: bigint): Uint8Array {
    const buffer = new ArrayBuffer(32);
    const dataView = new DataView(buffer);
    dataView.setBigUint64(0, (blockHeight >> 192n) & 0xffff_ffff_ffff_ffffn);
    dataView.setBigUint64(8, (blockHeight >> 128n) & 0xffff_ffff_ffff_ffffn);
    dataView.setBigUint64(16, (blockHeight >> 64n) & 0xffff_ffff_ffff_ffffn);
    dataView.setBigUint64(24, blockHeight & 0xffff_ffff_ffff_ffffn);
    return new Uint8Array(buffer);
}

// Fetch wallet balance
async function getWalletBalance(walletAddress: string): Promise<void> {
    try {
        const balance = await provider.getBalance(walletAddress);
        console.log(`Balance of ${walletAddress}: ${ethers.formatEther(balance)} ETH`);
    } catch (error) {
        console.error("Error fetching wallet balance:", error);
    }
}

// Fetch latest block number
async function latestBlockNumber(): Promise<void> {
    try {
        const blockNumber = await provider.getBlockNumber();
        console.log(`Latest Block Number: ${blockNumber}`);
    } catch (error) {
        console.error("Error fetching latest block number:", error);
    }
}

// Create timelock request and check if it's fulfilled
async function createTimelockRequest(): Promise<void> {
    try {
        // Create blocklockSender instance with proxy contract address
        const blocklockSender = new ethers.Contract(blocklockSenderAddr, BlocklockSender__factory.abi, provider);
        console.log("decryptionSender address from blocklockSender proxy", await blocklockSender.decryptionSender());

        // Create decryptionSender instance with proxy contract address
        const decryptionSender = new ethers.Contract(decryptionSenderAddr, DecryptionSender__factory.abi, provider);
        console.log("Version number from decryptionSender proxy", await decryptionSender.version());

        // Create mockBlocklockReceiver instance with implementation contract address
        const mockBlocklockReceiver = MockBlocklockReceiver__factory.connect(mockBlocklockReceiverAddr, signer);

        const blockHeight = BigInt(await provider.getBlockNumber() + 5);
        const msg = ethers.parseEther("21.3");
        const abiCoder = AbiCoder.defaultAbiCoder();
        const msgBytes = abiCoder.encode(["uint256"], [msg]);
        const encodedMessage = getBytes(msgBytes);
        const encodedConditions = blockHeightToBEBytes(blockHeight);
        const ciphertext = encrypt_towards_identity_g1(encodedMessage, encodedConditions, BLOCKLOCK_DEFAULT_PUBLIC_KEY, BLOCKLOCK_IBE_OPTS);

        const tx = await mockBlocklockReceiver.createTimelockRequest(blockHeight, encodeCiphertextToSolidity(ciphertext));
        const receipt = await tx.wait(1);
        if (!receipt) throw new Error("Transaction has not been mined");

        const reqId = await mockBlocklockReceiver.requestId();
        console.log("Created request id:", reqId);
        console.log("Request creation block height:", await provider.getBlockNumber());
        console.log("Desired decryption block height:", blockHeight);
        console.log("Is request in-flight?:", await decryptionSender.isInFlight(reqId));
    } catch (error) {
        console.error("Error creating timelock request:", error);
    }
}

// Replace pending transaction (currently commented out)
async function replacePendingTransaction(): Promise<void> {
    const txData = {
        to: "0x5d84b82b750B996BFC1FA7985D90Ae8Fbe773364",
        value: "0",
        chainId: 314159,
        nonce: 1420,
        gasLimit: 10000000000,
        gasPrice: 2000000000,
    };
    try {
        const tx = await signer.sendTransaction(txData);
        const receipt = await tx.wait(1);
        console.log(receipt);
    } catch (error) {
        console.error("Error replacing pending transaction:", error);
    }
}

// Fetch transaction count for a wallet
async function getTransactionCount(walletAddr: AddressLike): Promise<number> {
    try {
        return await provider.getTransactionCount(walletAddr);
    } catch (error) {
        console.error("Error fetching transaction count:", error);
        return -1; // Return a fallback value in case of error
    }
}

// Main execution flow
async function main(): Promise<void> {
    const walletAddr = await signer.getAddress();

    try {
        // Get latest block number
        await latestBlockNumber();

        // Get wallet ETH balance
        await getWalletBalance(walletAddr);

        // Create timelock request
        await createTimelockRequest();
    } catch (error) {
        console.error("Error during execution:", error);
    }
}

// Execute script
main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error(err);
        process.exit(1);
    });
