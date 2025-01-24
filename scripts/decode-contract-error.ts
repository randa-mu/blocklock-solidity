import { ethers } from "ethers";
import {} from "../typechain-types/src/decryption-requests/DecryptionSender"
import { DecryptionSender__factory } from "../typechain-types";

const abi = DecryptionSender__factory.abi
const iface = new ethers.Interface(abi);

// Data to decode
const errorData = "0x582000000000000000000000000062c9cf8ff30177d8479edab017f38017bebf10c2"
const errorArgs = iface.parseError(errorData);
console.log(errorArgs);
