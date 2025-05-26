import { JsonRpcProvider, ethers } from "ethers";
import 'dotenv/config'
import {
    DecryptionSender__factory,
    BlocklockSender__factory,
    MockBlocklockReceiver__factory
} from "../../typechain-types";

// Usage:
// yarn ts-node utils/mocks/fetch-contract-data.ts 

const RPC_URL = process.env.RPC_URL;

// polygon mainnet addresses
const blocklockSenderAddr = "0x82Fed730CbdeC5A2D8724F2e3b316a70A565e27e"
const decryptionSenderAddr = "0x41cF74811B6B326bAe4AC4Df5b829035CB8a05DA";
const mockBlocklockReceiverAddr = "0x1B7f32A7C3Ce1e0f732a2b016a4034528939e9Df";

// // filecoin calibration testnet addresses
// const blocklockSenderAddr = "0xF00aB3B64c81b6Ce51f8220EB2bFaa2D469cf702"
// const decryptionSenderAddr = "0x2474d71AB97F1189D0E0cc1b6EbF8118DCa83000";
// const mockBlocklockReceiverAddr = "0x228Be38159Fc2A30A98acfD2Eddc46E1afa67fdc";

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
        
        const walletAddr = await signer.getAddress()

        // Get latest block number
        await latestBlockNumber(provider);

        // Get wallet ETH balance
        await getWalletBalance(RPC_URL!, walletAddr);

        // Create blocklockSender instance with proxy contract address
        const blocklockSender = new ethers.Contract(blocklockSenderAddr, BlocklockSender__factory.abi, provider);
        // We can test that blocklockSender is pointing to the right contract on the network
        // cast call 0xF00aB3B64c81b6Ce51f8220EB2bFaa2D469cf702 "version()(string)" --rpc-url https://rpc.ankr.com/filecoin_testnet
        console.log("DecryptionSender address from blocklockSender proxy", await blocklockSender.decryptionSender());

        // Create decryptionSender instance with proxy contract address
        const decryptionSender = new ethers.Contract(decryptionSenderAddr, DecryptionSender__factory.abi, provider);
        console.log("Version number from decryptionSender proxy", await decryptionSender.version());

        // Create mockBlocklockReceiver instance with implementation contract address
        const mockBlocklockReceiverInstance = MockBlocklockReceiver__factory.connect(mockBlocklockReceiverAddr, signer);
        console.log("blocklockSender addr from mockBlocklockReceiverInstance", await mockBlocklockReceiverInstance.blocklock());
        console.log("Current requestId value from mockBlocklockReceiverInstance", await mockBlocklockReceiverInstance.requestId());
        console.log("Current plaintext value from mockBlocklockReceiverInstance", await mockBlocklockReceiverInstance.plainTextValue());
        console.log("is the current request id in flight?", await decryptionSender.isInFlight(await mockBlocklockReceiverInstance.requestId()));

        // Fetch request data for last request id in mockBlocklockReceiverInstance
        // const requestId = await mockBlocklockReceiverInstance.requestId();
        // console.log(await blocklockSender.getRequest(requestId))
        // console.log("\n", await decryptionSender.getRequest(requestId))

        // Fetch full request id lists
        const erroredRequestIds = await decryptionSender.getAllErroredRequestIds()
        console.log(`Errored request ids ${erroredRequestIds}`)

        const unfilfilledRequestIds = await decryptionSender.getAllUnfulfilledRequestIds()
        console.log(`Unfulfilled request ids ${unfilfilledRequestIds}`)

        const fulfilledRequestIds = await decryptionSender.getAllFulfilledRequestIds()
        console.log(`Fulfilled request ids ${fulfilledRequestIds}`)
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