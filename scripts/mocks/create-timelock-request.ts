import { JsonRpcProvider, ethers, AbiCoder, getBytes } from "ethers";
import 'dotenv/config'
import {
    DecryptionSender__factory,
    BlocklockSender__factory,
    MockBlocklockReceiver__factory,
} from "../../typechain-types";
import { encrypt_towards_identity_g1, Ciphertext } from "../crypto"
import { TypesLib as BlocklockTypes } from "../../typechain-types/src/blocklock/BlocklockSender"
import { IbeOpts } from "../crypto";
import { keccak_256 } from "@noble/hashes/sha3";

// Usage:
// yarn ts-node scripts/mocks/create-timelock-request.ts 

const RPC_URL = process.env.CALIBRATIONNET_RPC_URL;
// const walletAddr = "0x5d84b82b750B996BFC1FA7985D90Ae8Fbe773364"
const walletAddr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const blocklockSenderAddr = "0xfF66908E1d7d23ff62791505b2eC120128918F44"
const decryptionSenderAddr = "0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3";
const mockBlocklockReceiverAddr = "0x6f637EcB3Eaf8bEd0fc597Dc54F477a33BBCA72B";

// const RPC_URL = "http://127.0.0.1:8545"
// const walletAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

// const blocklockSenderAddr = "0xC6bA8C3233eCF65B761049ef63466945c362EdD2";
// const decryptionSenderAddr = "0xbCF26943C0197d2eE0E5D05c716Be60cc2761508";
// const mockBlocklockReceiverAddr = "0x0b48aF34f4c854F5ae1A3D587da471FeA45bAD52";

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

function blockHeightToBEBytes(blockHeight: bigint) {
    const buffer = new ArrayBuffer(32)
    const dataView = new DataView(buffer)
    dataView.setBigUint64(0, (blockHeight >> 192n) & 0xffff_ffff_ffff_ffffn)
    dataView.setBigUint64(8, (blockHeight >> 128n) & 0xffff_ffff_ffff_ffffn)
    dataView.setBigUint64(16, (blockHeight >> 64n) & 0xffff_ffff_ffff_ffffn)
    dataView.setBigUint64(24, blockHeight & 0xffff_ffff_ffff_ffffn)

    return new Uint8Array(buffer)
}

async function getWalletBalance(rpcUrl: string, walletAddress: string): Promise<void> {
    try {
        // Connect to the Ethereum network using the RPC URL
        const provider = new ethers.JsonRpcProvider(rpcUrl);

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
}

async function main() {
    try {
        // Create a provider using the RPC URL
        const provider = new ethers.JsonRpcProvider(RPC_URL);

        // Create a signer using the private key
        const signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

        // Get latest block number
        await latestBlockNumber(provider);

        // Get wallet ETH balance
        await getWalletBalance(RPC_URL!, walletAddr);

        // Create blocklockSender instance with proxy contract address
        const blocklockSender = new ethers.Contract(blocklockSenderAddr, BlocklockSender__factory.abi, provider);
        // cast call 0xfF66908E1d7d23ff62791505b2eC120128918F44 "version()(string)" --rpc-url https://rpc.ankr.com/filecoin_testnet
        console.log("decryptionSender address from blocklockSender proxy", await blocklockSender.decryptionSender());

        // Create decryptionSender instance with proxy contract address
        const decryptionSender = new ethers.Contract(decryptionSenderAddr, DecryptionSender__factory.abi, provider);
        console.log("Version number from decryptionSender proxy", await decryptionSender.version());

        // Create mockBlocklockReceiver instance with implementation contract address
        const mockBlocklockReceiver = MockBlocklockReceiver__factory.connect(mockBlocklockReceiverAddr, signer);

        // create a timelock request from mockBlocklockReceiver contract and check it is fulfilled by blocklock agent
        const blockHeight = BigInt(await provider.getBlockNumber() + 5);
        const msg = ethers.parseEther("4");
        const abiCoder = AbiCoder.defaultAbiCoder();
        const msgBytes = abiCoder.encode(["uint256"], [msg]);
        const encodedMessage = getBytes(msgBytes);
        const conditions = {
            blockHeight: blockHeight
        }
        const encodedConditions = blockHeightToBEBytes(conditions.blockHeight);
        const ct = encrypt_towards_identity_g1(encodedMessage, encodedConditions, BLOCKLOCK_DEFAULT_PUBLIC_KEY, BLOCKLOCK_IBE_OPTS);

        let tx = await mockBlocklockReceiver.connect(signer).createTimelockRequest(blockHeight, encodeCiphertextToSolidity(ct));
        let receipt = await tx.wait(1);
        if (!receipt) {
            throw new Error("transaction has not been mined");
        }
        const reqId = await mockBlocklockReceiver.requestId();
        console.log("Created blocklock request id on filecoin testnet", reqId);
        console.log("is created blocklock request id inFlight?", await decryptionSender.isInFlight(reqId));

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