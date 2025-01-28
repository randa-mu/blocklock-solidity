import { ethers } from "ethers";
import {} from "../typechain-types/src/decryption-requests/DecryptionSender"
import { DecryptionSender__factory } from "../typechain-types";

const abi = DecryptionSender__factory.abi
const iface = new ethers.Interface(abi);

// Data to decode
const errorData = "0x3fed05c5000000000000000000000000000000000000000000000000000000000000000b"
const errorArgs = iface.parseError(errorData);
console.log(errorArgs);
