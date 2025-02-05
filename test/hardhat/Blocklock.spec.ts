import {
  Ciphertext,
  encrypt_towards_identity_g1,
  G2,
  IbeOpts,
  BlsBn254,
  preprocess_decryption_key_g1,
} from "../../scripts/crypto";
import {
  MockBlocklockReceiver,
  MockBlocklockStringReceiver,
  SignatureSchemeAddressProvider,
  SignatureSender,
  BlocklockSender,
  BlocklockSignatureScheme,
  DecryptionSender,
  DecryptionSender__factory,
  BlocklockSender__factory,
} from "../../typechain-types";
import { TypesLib as BlocklockTypes } from "../../typechain-types/src/blocklock/BlocklockSender";
import { keccak_256 } from "@noble/hashes/sha3";
import dotenv from "dotenv";
import {
  getBytes,
  Signer,
  ZeroAddress,
  Interface,
  TransactionReceipt,
  isHexString,
  AbiCoder,
  EventFragment,
  Result,
  toUtf8Bytes,
} from "ethers";

dotenv.config();

const { expect } = require("chai");
const { ethers } = require("hardhat");

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

const blsKey = process.env.BLS_KEY;

function blockHeightToBEBytes(blockHeight: bigint) {
  // Assume a block height < 2**64
  const buffer = new ArrayBuffer(32);
  const dataView = new DataView(buffer);
  dataView.setBigUint64(0, (blockHeight >> 192n) & 0xffff_ffff_ffff_ffffn);
  dataView.setBigUint64(8, (blockHeight >> 128n) & 0xffff_ffff_ffff_ffffn);
  dataView.setBigUint64(16, (blockHeight >> 64n) & 0xffff_ffff_ffff_ffffn);
  dataView.setBigUint64(24, blockHeight & 0xffff_ffff_ffff_ffffn);

  return new Uint8Array(buffer);
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

function parseSolidityCiphertextStruct(ciphertext: BlocklockTypes.CiphertextStructOutput): Ciphertext {
  const uX0 = ciphertext.u.x[0];
  const uX1 = ciphertext.u.x[1];
  const uY0 = ciphertext.u.y[0];
  const uY1 = ciphertext.u.y[1];
  return {
    U: { x: { c0: uX0, c1: uX1 }, y: { c0: uY0, c1: uY1 } },
    V: getBytes(ciphertext.v),
    W: getBytes(ciphertext.w),
  };
}

function parseSolidityCiphertextString(ciphertext: string): Ciphertext {
  const ctBytes = getBytes(ciphertext);
  const ct: BlocklockTypes.CiphertextStructOutput = AbiCoder.defaultAbiCoder().decode(
    ["tuple(tuple(uint256[2] x, uint256[2] y) u, bytes v, bytes w)"],
    ctBytes,
  )[0];

  const uX0 = ct.u.x[0];
  const uX1 = ct.u.x[1];
  const uY0 = ct.u.y[0];
  const uY1 = ct.u.y[1];
  return {
    U: { x: { c0: uX0, c1: uX1 }, y: { c0: uY0, c1: uY1 } },
    V: getBytes(ct.v),
    W: getBytes(ct.w),
  };
}

function extractLogs<T extends Interface, E extends EventFragment>(
  iface: T,
  receipt: TransactionReceipt,
  contractAddress: string,
  event: E,
): Array<Result> {
  return receipt.logs
    .filter((log) => log.address.toLowerCase() === contractAddress.toLowerCase())
    .map((log) => iface.decodeEventLog(event, log.data, log.topics));
}

function extractSingleLog<T extends Interface, E extends EventFragment>(
  iface: T,
  receipt: TransactionReceipt,
  contractAddress: string,
  event: E,
): Result {
  const events = extractLogs(iface, receipt, contractAddress, event);
  if (events.length === 0) {
    throw Error(`contract at ${contractAddress} didn't emit the ${event.name} event`);
  }
  return events[0];
}

function encrypt(message: Uint8Array, blockHeight: bigint, pk: G2 = BLOCKLOCK_DEFAULT_PUBLIC_KEY): Ciphertext {
  const identity = blockHeightToBEBytes(blockHeight);
  return encrypt_towards_identity_g1(message, identity, pk, BLOCKLOCK_IBE_OPTS);
}

describe("BlocklockSender", function () {
  let blocklockReceiver: MockBlocklockReceiver;
  let blocklockStringReceiver: MockBlocklockStringReceiver;
  let blocklock: BlocklockSender;
  let decryptionSender: DecryptionSender;
  let schemeProvider: SignatureSchemeAddressProvider;
  let blocklockScheme: BlocklockSignatureScheme;

  let owner: Signer;

  const SCHEME_ID = "BN254-BLS-BLOCKLOCK";

  beforeEach(async () => {
    [owner] = await ethers.getSigners();

    schemeProvider = await ethers.deployContract("SignatureSchemeAddressProvider", [await owner.getAddress()]);
    await schemeProvider.waitForDeployment();

    blocklockScheme = await ethers.deployContract("BlocklockSignatureScheme");
    await blocklockScheme.waitForDeployment();
    await schemeProvider.updateSignatureScheme(SCHEME_ID, await blocklockScheme.getAddress());

    const DecryptionSenderImplementation = await ethers.getContractFactory("DecryptionSender");
    const decryptionSenderImplementation = await DecryptionSenderImplementation.deploy();
    await decryptionSenderImplementation.waitForDeployment();

    let UUPSProxy = await ethers.getContractFactory("UUPSProxy");
    const uupsProxy = await UUPSProxy.deploy(
      await decryptionSenderImplementation.getAddress(),
      DecryptionSenderImplementation.interface.encodeFunctionData("initialize", [
        [BLOCKLOCK_DEFAULT_PUBLIC_KEY.x.c0, BLOCKLOCK_DEFAULT_PUBLIC_KEY.x.c1],
        [BLOCKLOCK_DEFAULT_PUBLIC_KEY.y.c0, BLOCKLOCK_DEFAULT_PUBLIC_KEY.y.c1],
        await owner.getAddress(),
        await schemeProvider.getAddress(),
      ]),
    );
    await uupsProxy.waitForDeployment();
    decryptionSender = DecryptionSenderImplementation.attach(await uupsProxy.getAddress()); // DecryptionSender__factory.connect(await uupsProxy.getAddress(), owner);

    const BlocklockSenderImplementation = await ethers.getContractFactory("BlocklockSender");
    const blocklockSenderImplementation = await BlocklockSenderImplementation.deploy();
    await blocklockSenderImplementation.waitForDeployment();

    const uupsProxy2 = await UUPSProxy.deploy(
      await blocklockSenderImplementation.getAddress(),
      BlocklockSenderImplementation.interface.encodeFunctionData("initialize", [
        await owner.getAddress(),
        await decryptionSender.getAddress(),
      ]),
    );
    await uupsProxy2.waitForDeployment();
    blocklock = BlocklockSenderImplementation.attach(await uupsProxy2.getAddress());

    blocklockReceiver = await ethers.deployContract("MockBlocklockReceiver", [await blocklock.getAddress()]);
    await blocklockReceiver.waitForDeployment();

    blocklockStringReceiver = await ethers.deployContract("MockBlocklockStringReceiver", [
      await blocklock.getAddress(),
    ]);
    await blocklockStringReceiver.waitForDeployment();
  });

  async function encryptAndRegister(
    message: Uint8Array,
    blockHeight: bigint,
    pk: G2 = BLOCKLOCK_DEFAULT_PUBLIC_KEY,
  ): Promise<{
    id: string;
    receipt: any;
    ct: Ciphertext;
  }> {
    const ct = encrypt(message, blockHeight, pk);

    const tx = await blocklock.requestBlocklock(blockHeight, encodeCiphertextToSolidity(ct));
    const receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    const iface = BlocklockSender__factory.createInterface();
    const [requestID] = extractSingleLog(
      iface,
      receipt,
      await blocklock.getAddress(),
      iface.getEvent("BlocklockRequested"),
    );

    return {
      id: requestID.toString(),
      receipt: receipt,
      ct,
    };
  }

  it("can request blocklock decryption", async function () {
    let blockHeight = await ethers.provider.getBlockNumber();

    const msg = ethers.parseEther("4");
    const msgBytes = AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);
    // encodedMessage = 0x00000000000000000000000000000000000000000000000029a2241af62c0000

    const { id, receipt } = await encryptAndRegister(
      encodedMessage,
      BigInt(blockHeight + 2),
      BLOCKLOCK_DEFAULT_PUBLIC_KEY,
    );

    expect(BigInt(id) > BigInt(0)).to.be.equal(true);

    let req = await blocklock.getRequest(BigInt(id));
    expect(req.blockHeight).to.be.equal(BigInt(blockHeight + 2));

    const decryptionSenderIface = DecryptionSender__factory.createInterface();
    const [requestID, callback, schemeID, condition, ciphertext] = extractSingleLog(
      decryptionSenderIface,
      receipt,
      await decryptionSender.getAddress(),
      decryptionSenderIface.getEvent("DecryptionRequested"),
    );

    console.log(`received decryption request ${requestID}`);
    console.log(`call back address ${callback}, scheme id ${schemeID}`);

    const bls = await BlsBn254.create();
    const { pubKey, secretKey } = bls.createKeyPair(blsKey as `0x${string}`);

    const conditionBytes = isHexString(condition) ? getBytes(condition) : toUtf8Bytes(condition);
    const m = bls.hashToPoint(BLOCKLOCK_IBE_OPTS.dsts.H1_G1, conditionBytes);

    const hexCondition = Buffer.from(conditionBytes).toString("hex");
    blockHeight = BigInt("0x" + hexCondition);

    const parsedCiphertext = parseSolidityCiphertextString(ciphertext);

    const signature = bls.sign(m, secretKey).signature;
    const sig = bls.serialiseG1Point(signature);
    const sigBytes = AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [sig[0], sig[1]]);

    const decryption_key = preprocess_decryption_key_g1(parsedCiphertext, { x: sig[0], y: sig[1] }, BLOCKLOCK_IBE_OPTS);
    let tx = await decryptionSender.connect(owner).fulfilDecryptionRequest(requestID, decryption_key, sigBytes);
    const txreceipt = await tx.wait(1);
    if (!txreceipt) {
      throw new Error("transaction has not been mined");
    }

    const iface = BlocklockSender__factory.createInterface();
    const [, , , decryptionK] = extractSingleLog(
      iface,
      txreceipt,
      await blocklock.getAddress(),
      iface.getEvent("BlocklockCallbackSuccess"),
    );
    let test_ct: BlocklockTypes.CiphertextStruct = {
      u: { x: [...req.ciphertext.u.x], y: [...req.ciphertext.u.y] },
      v: req.ciphertext.v,
      w: req.ciphertext.w,
    };

    const decryptedM2 = getBytes(await blocklock.decrypt(test_ct, decryptionK));

    expect(Array.from(getBytes(encodedMessage))).to.have.members(Array.from(decryptedM2));
  });

  it("Should deploy the contracts with non zero addresses", async function () {
    expect(await owner.getAddress()).to.not.equal(ZeroAddress);
    expect(await schemeProvider.getAddress()).to.not.equal(ZeroAddress);
    expect(await blocklockReceiver.getAddress()).to.not.equal(ZeroAddress);
    expect(await blocklock.getAddress()).to.not.equal(ZeroAddress);
    expect(await decryptionSender.getAddress()).to.not.equal(ZeroAddress);
    expect(await blocklockScheme.getAddress()).to.not.equal(ZeroAddress);
  });

  it("can request blocklock decryption from user contract for uint256 and receive decryption key callback", async function () {
    let blockHeight = await ethers.provider.getBlockNumber();

    const msg = ethers.parseEther("4");
    const msgBytes = AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);
    // encodedMessage = 0x00000000000000000000000000000000000000000000000029a2241af62c0000

    const ct = encrypt(encodedMessage, BigInt(blockHeight + 2), BLOCKLOCK_DEFAULT_PUBLIC_KEY);

    let tx = await blocklockReceiver
      .connect(owner)
      .createTimelockRequest(BigInt(blockHeight + 2), encodeCiphertextToSolidity(ct));
    let receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    const decryptionSenderIface = DecryptionSender__factory.createInterface();
    const [requestID, callback, schemeID, condition, ciphertext] = extractSingleLog(
      decryptionSenderIface,
      receipt,
      await decryptionSender.getAddress(),
      decryptionSenderIface.getEvent("DecryptionRequested"),
    );

    console.log("callback and blocklock address", callback, await blocklock.getAddress());

    let req = await blocklock.getRequest(BigInt(requestID));
    expect(req.blockHeight).to.be.equal(BigInt(blockHeight + 2));

    console.log(`received decryption request ${requestID}`);
    console.log(`call back address ${callback}, scheme id ${schemeID}`);

    const bls = await BlsBn254.create();
    const { pubKey, secretKey } = bls.createKeyPair(blsKey as `0x${string}`);

    const conditionBytes = isHexString(condition) ? getBytes(condition) : toUtf8Bytes(condition);
    const m = bls.hashToPoint(BLOCKLOCK_IBE_OPTS.dsts.H1_G1, conditionBytes);

    const hexCondition = Buffer.from(conditionBytes).toString("hex");
    blockHeight = BigInt("0x" + hexCondition);

    const parsedCiphertext = parseSolidityCiphertextString(ciphertext);

    const signature = bls.sign(m, secretKey).signature;
    const sig = bls.serialiseG1Point(signature);
    const sigBytes = AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [sig[0], sig[1]]);

    const decryption_key = preprocess_decryption_key_g1(parsedCiphertext, { x: sig[0], y: sig[1] }, BLOCKLOCK_IBE_OPTS);

    tx = await decryptionSender.connect(owner).fulfilDecryptionRequest(requestID, decryption_key, sigBytes);
    receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    const iface = BlocklockSender__factory.createInterface();
    const [, , , decryptionK] = extractSingleLog(
      iface,
      receipt,
      await blocklock.getAddress(),
      iface.getEvent("BlocklockCallbackSuccess"),
    );

    let test_ct: BlocklockTypes.CiphertextStruct = {
      u: { x: [...req.ciphertext.u.x], y: [...req.ciphertext.u.y] },
      v: req.ciphertext.v,
      w: req.ciphertext.w,
    };

    const decryptedM2 = getBytes(await blocklock.decrypt(test_ct, decryptionK));

    expect(Array.from(getBytes(encodedMessage))).to.have.members(Array.from(decryptedM2));

    expect(await blocklockReceiver.plainTextValue()).to.be.equal(msg);
  });

  it("timelock request should revert if blocklock sender address is incorrect in blocklockReceiver", async function () {
    blocklockReceiver = await ethers.deployContract("MockBlocklockReceiver", [await owner.getAddress()]);
    await blocklockReceiver.waitForDeployment();

    let blockHeight = await ethers.provider.getBlockNumber();

    const msg = ethers.parseEther("4");
    const msgBytes = AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);
    // encodedMessage = 0x00000000000000000000000000000000000000000000000029a2241af62c0000

    const ct = encrypt(encodedMessage, BigInt(blockHeight + 2), BLOCKLOCK_DEFAULT_PUBLIC_KEY);

    await expect(
      blocklockReceiver.connect(owner).createTimelockRequest(BigInt(blockHeight + 2), encodeCiphertextToSolidity(ct)),
    ).to.be.reverted;
  });

  it("enumerable set can track multiple requests", async function () {
    let numberOfPendingRequests = await decryptionSender.getCountOfUnfulfilledRequestIds();
    let numberOfFulfilledRequests = await decryptionSender.getCountOfFulfilledRequestIds();
    let pendingRequestIds = await decryptionSender.getAllUnfulfilledRequestIds();
    let nonPendingRequestIds = await decryptionSender.getAllFulfilledRequestIds();

    expect(numberOfPendingRequests).to.be.equal(0);
    expect(numberOfFulfilledRequests).to.be.equal(0);
    expect(pendingRequestIds.length).to.be.equal(0);
    expect(nonPendingRequestIds.length).to.be.equal(0);

    let blockHeight = await ethers.provider.getBlockNumber();

    const msg = "mainnet launch soon";
    const msgBytes = AbiCoder.defaultAbiCoder().encode(["string"], [msg]);
    const encodedMessage = getBytes(msgBytes);

    const ct = encrypt(encodedMessage, BigInt(blockHeight + 2), BLOCKLOCK_DEFAULT_PUBLIC_KEY);
    const ct2 = encrypt(encodedMessage, BigInt(blockHeight + 3), BLOCKLOCK_DEFAULT_PUBLIC_KEY);

    let tx = await blocklockStringReceiver
      .connect(owner)
      .createTimelockRequest(BigInt(blockHeight + 2), encodeCiphertextToSolidity(ct));
    let receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    tx = await blocklockStringReceiver
      .connect(owner)
      .createTimelockRequest(BigInt(blockHeight + 3), encodeCiphertextToSolidity(ct2));
    receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    numberOfPendingRequests = await decryptionSender.getCountOfUnfulfilledRequestIds();
    numberOfFulfilledRequests = await decryptionSender.getCountOfFulfilledRequestIds();
    pendingRequestIds = await decryptionSender.getAllUnfulfilledRequestIds();
    nonPendingRequestIds = await decryptionSender.getAllFulfilledRequestIds();

    expect(numberOfPendingRequests).to.be.equal(2);
    expect(numberOfFulfilledRequests).to.be.equal(0);
    expect(pendingRequestIds.length).to.be.equal(2);
    expect(nonPendingRequestIds.length).to.be.equal(0);
    expect(pendingRequestIds[0]).to.be.equal(1);
    expect(pendingRequestIds[1]).to.be.equal(2);
    expect(await decryptionSender.isInFlight(1)).to.be.equal(true);
  });

  it("can request blocklock decryption from user contract for string and receive decryption key callback", async function () {
    let numberOfPendingRequests = await decryptionSender.getCountOfUnfulfilledRequestIds();
    let numberOfFulfilledRequests = await decryptionSender.getCountOfFulfilledRequestIds();
    let pendingRequestIds = await decryptionSender.getAllUnfulfilledRequestIds();
    let nonPendingRequestIds = await decryptionSender.getAllFulfilledRequestIds();

    expect(numberOfPendingRequests).to.be.equal(0);
    expect(numberOfFulfilledRequests).to.be.equal(0);
    expect(pendingRequestIds.length).to.be.equal(0);
    expect(nonPendingRequestIds.length).to.be.equal(0);
    
    let blockHeight = await ethers.provider.getBlockNumber();

    const msg = "mainnet launch soon";
    const msgBytes = AbiCoder.defaultAbiCoder().encode(["string"], [msg]);
    const encodedMessage = getBytes(msgBytes);

    const ct = encrypt(encodedMessage, BigInt(blockHeight + 2), BLOCKLOCK_DEFAULT_PUBLIC_KEY);

    let tx = await blocklockStringReceiver
      .connect(owner)
      .createTimelockRequest(BigInt(blockHeight + 2), encodeCiphertextToSolidity(ct));
    let receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    const decryptionSenderIface = DecryptionSender__factory.createInterface();
    const [requestID, callback, schemeID, condition, ciphertext] = extractSingleLog(
      decryptionSenderIface,
      receipt,
      await decryptionSender.getAddress(),
      decryptionSenderIface.getEvent("DecryptionRequested"),
    );

    numberOfPendingRequests = await decryptionSender.getCountOfUnfulfilledRequestIds();
    numberOfFulfilledRequests = await decryptionSender.getCountOfFulfilledRequestIds();
    pendingRequestIds = await decryptionSender.getAllUnfulfilledRequestIds();
    nonPendingRequestIds = await decryptionSender.getAllFulfilledRequestIds();

    expect(numberOfPendingRequests).to.be.equal(1);
    expect(numberOfFulfilledRequests).to.be.equal(0);
    expect(pendingRequestIds.length).to.be.equal(1);
    expect(nonPendingRequestIds.length).to.be.equal(0);
    
    expect(pendingRequestIds[0]).to.be.equal(1);

    console.log("callback and blocklock address", callback, await blocklock.getAddress());

    let req = await blocklock.getRequest(BigInt(requestID));
    expect(req.blockHeight).to.be.equal(BigInt(blockHeight + 2));

    console.log(`received decryption request ${requestID}`);
    console.log(`call back address ${callback}, scheme id ${schemeID}`);

    const bls = await BlsBn254.create();
    const { pubKey, secretKey } = bls.createKeyPair(blsKey as `0x${string}`);

    const conditionBytes = isHexString(condition) ? getBytes(condition) : toUtf8Bytes(condition);
    const m = bls.hashToPoint(BLOCKLOCK_IBE_OPTS.dsts.H1_G1, conditionBytes);

    const hexCondition = Buffer.from(conditionBytes).toString("hex");
    blockHeight = BigInt("0x" + hexCondition);

    const parsedCiphertext = parseSolidityCiphertextString(ciphertext);

    const signature = bls.sign(m, secretKey).signature;
    const sig = bls.serialiseG1Point(signature);
    const sigBytes = AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [sig[0], sig[1]]);

    const decryption_key = preprocess_decryption_key_g1(parsedCiphertext, { x: sig[0], y: sig[1] }, BLOCKLOCK_IBE_OPTS);

    tx = await decryptionSender.connect(owner).fulfilDecryptionRequest(requestID, decryption_key, sigBytes);
    receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    const iface = BlocklockSender__factory.createInterface();
    const [, decryptionBlockHeight, decryptionCiphertext, decryptionK] = extractSingleLog(
      iface,
      receipt,
      await blocklock.getAddress(),
      iface.getEvent("BlocklockCallbackSuccess"),
    );

    numberOfPendingRequests = await decryptionSender.getCountOfUnfulfilledRequestIds();
    numberOfFulfilledRequests = await decryptionSender.getCountOfFulfilledRequestIds();
    pendingRequestIds = await decryptionSender.getAllUnfulfilledRequestIds();
    nonPendingRequestIds = await decryptionSender.getAllFulfilledRequestIds();

    expect(numberOfPendingRequests).to.be.equal(0);
    expect(numberOfFulfilledRequests).to.be.equal(1);
    expect(pendingRequestIds.length).to.be.equal(0);
    expect(nonPendingRequestIds.length).to.be.equal(1);

    expect(nonPendingRequestIds[0]).to.be.equal(1);
    expect(await decryptionSender.isInFlight(1)).to.be.equal(false);

    // ciphertext should not be deleted after successful callback
    req = await blocklock.getRequest(BigInt(requestID));
    expect(req.blockHeight).to.be.equal(Number(decryptionBlockHeight));
    expect(req.ciphertext).to.deep.equal(decryptionCiphertext);
    expect(decryptionK).to.deep.equal(req.decryptionKey);

    let test_ct: BlocklockTypes.CiphertextStruct = {
      u: { x: [...req.ciphertext.u.x], y: [...req.ciphertext.u.y] },
      v: req.ciphertext.v,
      w: req.ciphertext.w,
    };

    const decryptedM2 = getBytes(await blocklock.decrypt(test_ct, decryptionK));

    expect(Array.from(getBytes(encodedMessage))).to.have.members(Array.from(decryptedM2));

    expect(await blocklockStringReceiver.plainTextValue()).to.be.equal(msg);
    console.log(await blocklockStringReceiver.plainTextValue(), msg);
  });
});
