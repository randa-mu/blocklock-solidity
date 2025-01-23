import { ethers } from "ethers";
import 'dotenv/config'

const RPC_URL = process.env.CALIBRATIONNET_RPC_URL;

async function main() {
    try {
        // Create a provider using the RPC URL
        const provider = new ethers.JsonRpcProvider(RPC_URL);

        // Fetch the latest block number
        const latestBlockNumber = await provider.getBlockNumber();
        console.log(`Latest Block Number: ${latestBlockNumber}`);
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
