import { JsonRpcProvider, ethers, AbiCoder, getBytes } from "ethers";
import 'dotenv/config'
import {
    DecryptionSender__factory,
    BlocklockSender__factory,
    MockBlocklockReceiver__factory,
} from "../../typechain-types";

// Usage:
// yarn ts-node scripts/mocks/fetch-contract-data.ts <REQUEST_ID>

// Retrieve requestId from command line argument (default to 1 if not passed)
const requestId = process.argv[2] || "1"; // Default to 1 if not provided
const RPC_URL = process.env.CALIBRATIONNET_RPC_URL;

const walletAddr = "0x5d84b82b750B996BFC1FA7985D90Ae8Fbe773364";
const blocklockSenderAddr = "0xfF66908E1d7d23ff62791505b2eC120128918F44";
const decryptionSenderAddr = "0x9297Bb1d423ef7386C8b2e6B7BdE377977FBedd3";
const mockBlocklockReceiverAddr = "0x6f637EcB3Eaf8bEd0fc597Dc54F477a33BBCA72B";

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
        console.log("blocklockSender addr from mockBlocklockReceiver", await mockBlocklockReceiver.blocklock());
        console.log("Plaintext value from mockBlocklockReceiver", await mockBlocklockReceiver.plainTextValue());
        console.log("Current requestId value from mockBlocklockReceiver", await mockBlocklockReceiver.requestId());
        console.log("is request id in flight?", await decryptionSender.isInFlight(requestId));

        // You can now use the requestId variable
        console.log(`Fetching data for request ID ${requestId}:`);

        // Fetch request data based on requestId
        console.log("\nFetching request details for requestId:", requestId);
        console.log(await blocklockSender.getRequest(requestId));
        console.log("\n", await decryptionSender.getRequest(requestId));

        const erroredRequestIds = await decryptionSender.getAllErroredRequestIds();
        console.log(erroredRequestIds);

        const unfilfilledRequestIds = await decryptionSender.getAllUnfulfilledRequestIds();
        console.log(unfilfilledRequestIds);

        const fulfilledRequestIds = await decryptionSender.getAllFulfilledRequestIds();
        console.log(fulfilledRequestIds);
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
