import {
  MockBlocklockReceiver__factory,
  BlocklockSender__factory,
  BlocklockSignatureScheme__factory,
  DecryptionSender__factory,
  SignatureSchemeAddressProvider__factory,
  UUPSProxy__factory,
} from "../../typechain-types";
import { TypesLib as BlocklockTypes } from "../../typechain-types/src/blocklock/BlocklockSender";
import { BlsBn254, serialiseG2Point } from "../../utils/crypto/bls-bn254";
import {
  IbeOpts,
  preprocess_decryption_key_g1,
  encrypt_towards_identity_g1,
  Ciphertext,
} from "../../utils/crypto/ibe-bn254";
import { keccak_256 } from "@noble/hashes/sha3";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import dotenv from "dotenv";
import {
  ZeroAddress,
  getBytes,
  isHexString,
  toUtf8Bytes,
  AbiCoder,
  Signer,
  EthersError,
  EventFragment,
  Interface,
  Result,
  TransactionReceipt,
  Provider,
} from "ethers";
import { ethers } from "hardhat";

const { expect } = require("chai");

dotenv.config();

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

const BLOCKLOCK_IBE_OPTS: IbeOpts = {
  hash: keccak_256,
  k: 128,
  expand_fn: "xmd",
  dsts: {
    H1_G1: Buffer.from(
      "BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_0x0000000000000000000000000000000000000000000000000000000000007a69_",
    ),
    H2: Buffer.from(
      "BLOCKLOCK_BN254_XMD:KECCAK-256_H2_0x0000000000000000000000000000000000000000000000000000000000007a69_",
    ),
    H3: Buffer.from(
      "BLOCKLOCK_BN254_XMD:KECCAK-256_H3_0x0000000000000000000000000000000000000000000000000000000000007a69_",
    ),
    H4: Buffer.from(
      "BLOCKLOCK_BN254_XMD:KECCAK-256_H4_0x0000000000000000000000000000000000000000000000000000000000007a69_",
    ),
  },
};

const blsKey = process.env.BLS_PRIVATE_KEY;
const SCHEME_ID = "BN254-BLS-BLOCKLOCK";

let wallet: SignerWithAddress;

describe("Blocklock integration tests", () => {
  beforeEach(async () => {
    // Use the first signer as wallet
    [wallet] = await ethers.getSigners();
  });

  it("should get correct network information", async () => {
    const network = await ethers.provider.getNetwork();
    expect(network.chainId).to.equal(31337n); // Default chainId
  });

  it("should get valid address for signer", async () => {
    expect(await wallet.getAddress()).not.to.equal(ZeroAddress);
  });

  it("can request blocklock decryption with subscription funding from user contract and decrypt on-chain", async () => {
    /** Smart Contract Deployments */

    // deploy signature scheme address provider
    const SignatureSchemeAddressProvider = new ethers.ContractFactory(
      SignatureSchemeAddressProvider__factory.abi,
      SignatureSchemeAddressProvider__factory.bytecode,
      wallet,
    );
    const signatureSchemeAddressProvider = await SignatureSchemeAddressProvider.deploy(await wallet.getAddress());
    await signatureSchemeAddressProvider.waitForDeployment();
    const schemeProviderAddr = await signatureSchemeAddressProvider.getAddress();
    console.log(schemeProviderAddr);
    // deploy blocklock scheme
    const BlocklockScheme = new ethers.ContractFactory(
      BlocklockSignatureScheme__factory.abi,
      BlocklockSignatureScheme__factory.bytecode,
      wallet,
    );
    const blocklockScheme = await BlocklockScheme.deploy(
      [blocklock_default_pk.x.c0, blocklock_default_pk.x.c1],
      [blocklock_default_pk.y.c0, blocklock_default_pk.y.c1],
    );
    await blocklockScheme.waitForDeployment();
    const scheme = BlocklockSignatureScheme__factory.connect(await blocklockScheme.getAddress(), wallet);

    expect(await scheme.DST()).to.be.equal(uint8ArrayToHexString(BLOCKLOCK_IBE_OPTS.dsts.H1_G1));

    const schemeProviderContract = SignatureSchemeAddressProvider__factory.connect(schemeProviderAddr, wallet);
    await schemeProviderContract.updateSignatureScheme(SCHEME_ID, await blocklockScheme.getAddress());

    // deploy decryption sender
    const DecryptionSender = new ethers.ContractFactory(
      DecryptionSender__factory.abi,
      DecryptionSender__factory.bytecode,
      wallet,
    );
    const decryptionSenderImplementation = await DecryptionSender.deploy();
    await decryptionSenderImplementation.waitForDeployment();

    let UUPSProxy = new ethers.ContractFactory(UUPSProxy__factory.abi, UUPSProxy__factory.bytecode, wallet);
    const decryptionSenderProxy = await UUPSProxy.deploy(
      await decryptionSenderImplementation.getAddress(),
      DecryptionSender.interface.encodeFunctionData("initialize", [await wallet.getAddress(), schemeProviderAddr]),
    );
    await decryptionSenderProxy.waitForDeployment();
    const decryptionSender = DecryptionSender.attach(await decryptionSenderProxy.getAddress());
    const decryptionSenderInstance = DecryptionSender__factory.connect(await decryptionSender.getAddress(), wallet);

    // deploy blocklock sender
    const BlocklockSender = new ethers.ContractFactory(
      BlocklockSender__factory.abi,
      BlocklockSender__factory.bytecode,
      wallet,
    );
    const blocklockSenderImplementation = await BlocklockSender.deploy();
    await blocklockSenderImplementation.waitForDeployment();

    const blocklockSenderProxy = await UUPSProxy.deploy(
      await blocklockSenderImplementation.getAddress(),
      BlocklockSender.interface.encodeFunctionData("initialize", [
        await wallet.getAddress(),
        await decryptionSender.getAddress(),
      ]),
    );
    await blocklockSenderProxy.waitForDeployment();
    const blocklockSender = BlocklockSender__factory.connect(await blocklockSenderProxy.getAddress(), wallet);

    // configure request fees parameters
    const maxGasLimit = 500_000;
    const gasAfterPaymentCalculation = 400_000;
    const fulfillmentFlatFeeNativePPM = 1_000_000;
    const weiPerUnitGas = 3_000_000;
    const blsPairingCheckOverhead = 800_000;
    const nativePremiumPercentage = 10;
    const gasForCallExactCheck = 5_000;

    await blocklockSender.setConfig(
      maxGasLimit,
      gasAfterPaymentCalculation,
      fulfillmentFlatFeeNativePPM,
      weiPerUnitGas,
      blsPairingCheckOverhead,
      nativePremiumPercentage,
      gasForCallExactCheck,
    );

    // deploy user mock decryption receiver contract
    const MockBlocklockReceiver = new ethers.ContractFactory(
      MockBlocklockReceiver__factory.abi,
      MockBlocklockReceiver__factory.bytecode,
      wallet,
    );
    const mockBlocklockReceiver = await MockBlocklockReceiver.deploy(await blocklockSender.getAddress());
    await mockBlocklockReceiver.waitForDeployment();

    // User or client side
    const mockBlocklockReceiverInstance = MockBlocklockReceiver__factory.connect(
      await mockBlocklockReceiver.getAddress(),
      wallet,
    );

    expect(await mockBlocklockReceiverInstance.plainTextValue()).to.be.equal(BigInt(0));
    expect(await mockBlocklockReceiverInstance.blocklock()).to.be.equal(await blocklockSender.getAddress());

    const blockHeight = BigInt((await ethers.provider.getBlockNumber()) + 10);
    console.log("block height", blockHeight);

    // condition bytes
    const types = ["string", "uint256"]; // "B" is a string, and blockHeight is a uint256
    const values = ["B", blockHeight];
    const encodedCondition = ethers.AbiCoder.defaultAbiCoder().encode(types, values);
    console.log(values, encodedCondition);

    // identity for IBE
    // encrypt_towards_identity_g1 expects a uint8Array as input for the identity
    const identity = getBytes(encodedCondition);

    // message bytes
    const msg = ethers.parseEther("3"); // BigInt for 3 ETH
    const msgBytes = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);

    // generate Ciphertext
    const ct = encrypt_towards_identity_g1(encodedMessage, identity, blocklock_default_pk, BLOCKLOCK_IBE_OPTS);

    // create and fund subscription
    await mockBlocklockReceiverInstance
      .connect(wallet)
      .createSubscriptionAndFundNative({ value: ethers.parseEther("3") });

    // make direct funding request with enough callbackGasLimit to cover BLS operations in call to decrypt() function
    // in receiver contract
    const callbackGasLimit = 400_000;

    // used to check that the correct request estimated price based on network gas price is collected from subscription
    const requestPrice = await blocklockSender.calculateRequestPriceNative(callbackGasLimit);

    let tx = await mockBlocklockReceiverInstance
      .connect(wallet)
      .createTimelockRequestWithSubscription(callbackGasLimit, encodedCondition, encodeCiphertextToSolidity(ct));

    let receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }

    // Blocklock agent or server side
    let blocklockRequestStatus = await blocklockSender.getRequest(1n);
    console.log(blocklockRequestStatus!.condition);
    expect(blocklockRequestStatus!.condition).to.be.equal(encodedCondition);
    expect(blocklockRequestStatus?.decryptionKey.length).to.be.equal(2);

    const decryptionSenderIface = DecryptionSender__factory.createInterface();
    const [requestID, callback, schemeID, condition, ciphertext] = extractSingleLog(
      decryptionSenderIface,
      receipt,
      await decryptionSender.getAddress(),
      decryptionSenderIface.getEvent("DecryptionRequested"),
    );
    console.log(`received decryption request id ${requestID}`);
    console.log(`blocklock request id ${blocklockRequestStatus?.decryptionRequestId}`);
    console.log(`callback address ${callback}, scheme id ${schemeID}`);

    const bls = await BlsBn254.create();
    const { pubKey, secretKey } = bls.createKeyPair(blsKey as `0x${string}`);
    const conditionBytes = isHexString(condition) ? getBytes(condition) : toUtf8Bytes(condition);

    const m = bls.hashToPoint(BLOCKLOCK_IBE_OPTS.dsts.H1_G1, conditionBytes);
    const parsedCiphertext = parseSolidityCiphertextString(ciphertext);
    const signature = bls.sign(m, secretKey).signature;
    const sig = bls.serialiseG1Point(signature);
    const sigBytes = AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [sig[0], sig[1]]);
    const decryption_key = preprocess_decryption_key_g1(parsedCiphertext, { x: sig[0], y: sig[1] }, BLOCKLOCK_IBE_OPTS);

    // fulfill the conditional encryption request if profitable
    const estimatedGas = await decryptionSenderInstance
      .connect(wallet)
      .fulfillDecryptionRequest.estimateGas(requestID, decryption_key, sigBytes);

    const estimatedGasWithCallbackGasLimit = BigInt(estimatedGas) + BigInt(callbackGasLimit);

    // Fetch current gas pricing (EIP-1559 compatible)
    const feeData = await wallet.provider.getFeeData();
    const maxFeePerGas = feeData.maxFeePerGas!;
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!;

    const subscriptionId = await mockBlocklockReceiverInstance.subscriptionId();
    const [nativeBalance, , ,] = await blocklockSender.getSubscription(subscriptionId);
    const userPayment = nativeBalance; // for subscription, we check the subscription balance using the subscription id

    const baseFeePerGas = (await wallet.provider.getBlock("latest"))?.baseFeePerGas!;
    const effectiveGasPrice =
      maxFeePerGas < baseFeePerGas + maxPriorityFeePerGas ? maxFeePerGas : baseFeePerGas + maxPriorityFeePerGas;

    // It is best to calculate if it's profitable to execute with buffer
    // as the transaction could fail without adding the buffer if the actual gas used is
    // higher than the estimatedGasWithCallbackGasLimit.
    // It is also safer to add a buffer to the estimatedGasWithCallbackGasLimit, not just estimatedGas
    const gasBuffer = (estimatedGasWithCallbackGasLimit * 120n) / 100n; // 20% buffer
    const expectedTxCost = gasBuffer * effectiveGasPrice;
    const profitAfterTx = BigInt(userPayment) - BigInt(expectedTxCost); // checking user subscription balance can cover the expected transaction cost

    // Define the minimum profit margin threshold (e.g., 10%)
    const profitThresholdPercent = 10n;

    // Compute profit percentage
    const profitPercent = (profitAfterTx * 100n) / BigInt(userPayment);

    // Expect profit to meet or exceed the threshold
    expect(profitPercent).to.be.gte(profitThresholdPercent);

    console.log("Profit after tx in eth", ethers.formatEther(profitAfterTx.toString()));
    console.log("Expected tx cost in eth", ethers.formatEther(expectedTxCost.toString()));
    console.log("Native balance before tx:", ethers.formatEther(nativeBalance.toString()));

    // transaction passes if we add buffer to the gas limit
    tx = await decryptionSenderInstance.connect(wallet).fulfillDecryptionRequest(requestID, decryption_key, sigBytes, {
      gasLimit: gasBuffer,
      maxFeePerGas,
      maxPriorityFeePerGas,
    });
    const [success, txReceipt] = await checkTxMined(tx.hash, wallet.provider);
    expect(success).to.be.equal(true);

    const [nativeBalanceAfterTx, , ,] = await blocklockSender.getSubscription(subscriptionId);
    console.log("Native balance after tx:", ethers.formatEther(nativeBalanceAfterTx.toString()));
    console.log("Actual amount paid for tx:", ethers.formatEther(nativeBalance - nativeBalanceAfterTx));

    console.log(requestPrice);
    console.log("bal after", nativeBalance - nativeBalanceAfterTx);

    // amount deducted from subscription should be higher than actual gas used * gas price
    // and higher or equal to request price estimate
    expect(nativeBalance - nativeBalanceAfterTx).to.be.gt(txReceipt!.gasUsed * effectiveGasPrice);
    expect(requestPrice).to.be.lte(nativeBalance - nativeBalanceAfterTx);

    console.log("Estimated gas:", estimatedGas.toString());
    console.log("Callback gas limit:", callbackGasLimit.toString());
    console.log("Estimated gas + Callback gas limit:", estimatedGasWithCallbackGasLimit.toString());
    console.log("Actual gas used:", txReceipt!.gasUsed.toString());

    // The actual gas used is always higher than estimated gas
    // while in hardhat tests, the estimated gas is equal to the actual gas used
    // increasing the callback gas limit increases the estimated gas slightly with a chance that the
    // estimated gas plus callback gas limit could be higher than actual gas used.
    // Also, depending on what the callback gas limit is set to, the actual gas used could be higher than
    // estimated gas plus callback gas limit.
    expect(txReceipt!.gasUsed).to.be.lte(estimatedGas);
    expect(estimatedGas).to.be.gt(callbackGasLimit);
    expect(txReceipt!.gasUsed).to.be.lt(estimatedGasWithCallbackGasLimit);

    // Verify logs and request results
    const iface = BlocklockSender__factory.createInterface();
    const [, , ,] = extractSingleLog(
      iface,
      txReceipt!,
      await blocklockSender.getAddress(),
      iface.getEvent("BlocklockCallbackSuccess"),
    );

    blocklockRequestStatus = await blocklockSender.getRequest(1n);
    expect(blocklockRequestStatus!.condition).to.be.equal(encodedCondition);
    expect(blocklockRequestStatus?.decryptionKey).to.not.equal(undefined);
    expect(blocklockRequestStatus?.decryptionKey.length).to.be.equal(66);
    expect(await mockBlocklockReceiverInstance.plainTextValue()).to.be.equal(BigInt(msg));
  });

  it("can request blocklock decryption with direct funding from user contract and decrypt on-chain", async () => {
    /** Smart Contract Deployments */
    // deploy signature scheme address provider
    const SignatureSchemeAddressProvider = new ethers.ContractFactory(
      SignatureSchemeAddressProvider__factory.abi,
      SignatureSchemeAddressProvider__factory.bytecode,
      wallet,
    );
    const signatureSchemeAddressProvider = await SignatureSchemeAddressProvider.deploy(await wallet.getAddress());
    await signatureSchemeAddressProvider.waitForDeployment();
    const schemeProviderAddr = await signatureSchemeAddressProvider.getAddress();

    // deploy blocklock scheme
    const BlocklockScheme = new ethers.ContractFactory(
      BlocklockSignatureScheme__factory.abi,
      BlocklockSignatureScheme__factory.bytecode,
      wallet,
    );
    const blocklockScheme = await BlocklockScheme.deploy(
      [blocklock_default_pk.x.c0, blocklock_default_pk.x.c1],
      [blocklock_default_pk.y.c0, blocklock_default_pk.y.c1],
    );
    await blocklockScheme.waitForDeployment();
    const schemeProviderContract = SignatureSchemeAddressProvider__factory.connect(schemeProviderAddr, wallet);
    await schemeProviderContract.updateSignatureScheme(SCHEME_ID, await blocklockScheme.getAddress());
    // deploy decryption sender
    const DecryptionSender = new ethers.ContractFactory(
      DecryptionSender__factory.abi,
      DecryptionSender__factory.bytecode,
      wallet,
    );
    const decryptionSenderImplementation = await DecryptionSender.deploy();
    await decryptionSenderImplementation.waitForDeployment();
    let UUPSProxy = new ethers.ContractFactory(UUPSProxy__factory.abi, UUPSProxy__factory.bytecode, wallet);
    const uupsProxy = await UUPSProxy.deploy(
      await decryptionSenderImplementation.getAddress(),
      DecryptionSender.interface.encodeFunctionData("initialize", [await wallet.getAddress(), schemeProviderAddr]),
    );
    await uupsProxy.waitForDeployment();
    const decryptionSender = DecryptionSender.attach(await uupsProxy.getAddress());
    const decryptionSenderInstance = DecryptionSender__factory.connect(await decryptionSender.getAddress(), wallet);
    // deploy blocklock sender
    const BlocklockSender = new ethers.ContractFactory(
      BlocklockSender__factory.abi,
      BlocklockSender__factory.bytecode,
      wallet,
    );
    const blocklockSenderImplementation = await BlocklockSender.deploy();
    await blocklockSenderImplementation.waitForDeployment();
    const uupsProxy2 = await UUPSProxy.deploy(
      await blocklockSenderImplementation.getAddress(),
      BlocklockSender.interface.encodeFunctionData("initialize", [
        await wallet.getAddress(),
        await decryptionSender.getAddress(),
      ]),
    );
    await uupsProxy2.waitForDeployment();

    const blocklockSender = BlocklockSender__factory.connect(await uupsProxy2.getAddress(), wallet);

    // configure request fees parameters
    const maxGasLimit = 500_000;
    const gasAfterPaymentCalculation = 400_000;
    const fulfillmentFlatFeeNativePPM = 1_000_000;
    const weiPerUnitGas = 3_000_000;
    const blsPairingCheckOverhead = 800_000;
    const nativePremiumPercentage = 10;
    const gasForCallExactCheck = 5_000;

    await blocklockSender
      .connect(wallet)
      .setConfig(
        maxGasLimit,
        gasAfterPaymentCalculation,
        fulfillmentFlatFeeNativePPM,
        weiPerUnitGas,
        blsPairingCheckOverhead,
        nativePremiumPercentage,
        gasForCallExactCheck,
      );

    // deploy user mock decryption receiver contract
    const MockBlocklockReceiver = new ethers.ContractFactory(
      MockBlocklockReceiver__factory.abi,
      MockBlocklockReceiver__factory.bytecode,
      wallet,
    );
    const mockBlocklockReceiver = await MockBlocklockReceiver.deploy(await blocklockSender.getAddress());
    await mockBlocklockReceiver.waitForDeployment();

    /** Blocklock js Integration */
    // User or client side
    const mockBlocklockReceiverInstance = MockBlocklockReceiver__factory.connect(
      await mockBlocklockReceiver.getAddress(),
      wallet,
    );
    expect(await mockBlocklockReceiverInstance.plainTextValue()).to.equal(BigInt(0));

    const blockHeight = BigInt((await ethers.provider.getBlockNumber()) + 10);
    console.log("block height", blockHeight);

    // condition bytes
    const types = ["string", "uint256"]; // "B" is a string, and blockHeight is a uint256
    const values = ["B", blockHeight];
    const encodedCondition = ethers.AbiCoder.defaultAbiCoder().encode(types, values);
    console.log(values, encodedCondition);

    // identity for IBE
    // encrypt_towards_identity_g1 expects a uint8Array as input for the identity
    const identity = getBytes(encodedCondition);

    // message bytes
    const msg = ethers.parseEther("3"); // BigInt for 3 ETH
    const msgBytes = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);

    // generate Ciphertext
    const ct = encrypt_towards_identity_g1(encodedMessage, identity, blocklock_default_pk, BLOCKLOCK_IBE_OPTS);

    // make direct funding request with enough callbackGasLimit to cover BLS operations in call to decrypt() function
    // in receiver contract
    const callbackGasLimit = 500_000;

    let tx = await mockBlocklockReceiverInstance
      .connect(wallet)
      .createTimelockRequestWithDirectFunding(callbackGasLimit, encodedCondition, encodeCiphertextToSolidity(ct), {
        value: ethers.parseEther("2")
      });

    let receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }
    // Blocklock agent or server side
    const blockRequest = await blocklockSender.getRequest(1n);
    expect(blockRequest!.condition).to.equal(encodedCondition);

    let blocklockRequestStatus = await blocklockSender.getRequest(1n);
    console.log(blocklockRequestStatus!.condition);
    expect(blocklockRequestStatus!.condition).to.equal(encodedCondition);
    expect(blocklockRequestStatus?.decryptionKey.length).to.equal(2);

    const decryptionSenderIface = DecryptionSender__factory.createInterface();
    const [requestID, callback, schemeID, condition, ciphertext] = extractSingleLog(
      decryptionSenderIface,
      receipt,
      await decryptionSender.getAddress(),
      decryptionSenderIface.getEvent("DecryptionRequested"),
    );
    console.log(`received decryption request id ${requestID}`);
    console.log(`blocklock request id ${blockRequest?.decryptionRequestId}`);
    console.log(`callback address ${callback}, scheme id ${schemeID}`);
    const bls = await BlsBn254.create();
    const { pubKey, secretKey } = bls.createKeyPair(blsKey as `0x${string}`);

    const pubKeySerialised = serialiseG2Point(pubKey);
    expect(pubKeySerialised[0]).to.equal(blocklock_default_pk.x.c0);
    expect(pubKeySerialised[1]).to.equal(blocklock_default_pk.x.c1);
    expect(pubKeySerialised[2]).to.equal(blocklock_default_pk.y.c0);
    expect(pubKeySerialised[3]).to.equal(blocklock_default_pk.y.c1);

    const conditionBytes = isHexString(condition) ? getBytes(condition) : toUtf8Bytes(condition);

    const m = bls.hashToPoint(BLOCKLOCK_IBE_OPTS.dsts.H1_G1, conditionBytes);
    const parsedCiphertext = parseSolidityCiphertextString(ciphertext);
    console.log("Ciphertext", parsedCiphertext.U, toHexString(parsedCiphertext.V), toHexString(parsedCiphertext.W));
    const signature = bls.sign(m, secretKey).signature;
    const sig = bls.serialiseG1Point(signature);
    const sigBytes = AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [sig[0], sig[1]]);
    console.log("signature", sigBytes);
    const decryption_key = preprocess_decryption_key_g1(parsedCiphertext, { x: sig[0], y: sig[1] }, BLOCKLOCK_IBE_OPTS);
    console.log("decryption key", toHexString(decryption_key));

    // fulfill the conditional encryption request if profitable
    const estimatedGas = await decryptionSenderInstance
      .connect(wallet)
      .fulfillDecryptionRequest.estimateGas(requestID, decryption_key, sigBytes);
    const estimatedGasWithCallbackGasLimit = BigInt(estimatedGas) + BigInt(callbackGasLimit);

    // Fetch current gas pricing (EIP-1559 compatible)
    const feeData = await wallet.provider.getFeeData();
    const maxFeePerGas = feeData.maxFeePerGas!;
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!;
    const userPayment = blocklockRequestStatus.directFundingFeePaid;

    const baseFeePerGas = (await wallet.provider.getBlock("latest"))?.baseFeePerGas!;
    const effectiveGasPrice =
      maxFeePerGas < baseFeePerGas + maxPriorityFeePerGas ? maxFeePerGas : baseFeePerGas + maxPriorityFeePerGas;

    // Calculate if it's profitable to execute without buffer
    let expectedTxCost = estimatedGasWithCallbackGasLimit * effectiveGasPrice;
    let profitAfterTx = BigInt(userPayment) - BigInt(expectedTxCost);

    // Define the minimum profit margin threshold (e.g., 10%)
    const profitThresholdPercent = 10n;

    // Compute profit percentage
    let profitPercent = (profitAfterTx * 100n) / BigInt(userPayment);

    // Expect profit to meet or exceed the threshold
    expect(profitPercent).to.be.gte(profitThresholdPercent);

    // Calculate if it's profitable to execute with buffer
    // It is best to calculate if it's profitable to execute with buffer
    // as in some scenarios or chains, the transaction could fail without adding the buffer if the actual gas used is
    // higher than the estimatedGasWithCallbackGasLimit.
    // It is also safer to add a buffer to the estimatedGasWithCallbackGasLimit, not just estimatedGas
    const gasBuffer = (estimatedGasWithCallbackGasLimit * 120n) / 100n; // 20% buffer
    expectedTxCost = gasBuffer * effectiveGasPrice;
    profitAfterTx = BigInt(userPayment) - BigInt(expectedTxCost);

    // Compute profit percentage
    profitPercent = (profitAfterTx * 100n) / BigInt(userPayment);

    // Expect profit to meet or exceed the threshold
    expect(profitPercent).to.be.gte(profitThresholdPercent);

    // transaction passes whether we add buffer to the gas limit or don't
    // because the actual gas used == estimated gas without callback gas limit
    tx = await decryptionSenderInstance.connect(wallet).fulfillDecryptionRequest(requestID, decryption_key, sigBytes, {
      gasLimit: gasBuffer,
      maxFeePerGas,
      maxPriorityFeePerGas,
    });
    const [success, txReceipt] = await checkTxMined(tx.hash, wallet.provider);
    expect(success).to.be.equal(true);

    console.log("Estimated gas:", estimatedGas.toString());
    console.log("Callback gas limit:", callbackGasLimit.toString());
    console.log("Estimated gas + Callback gas limit:", estimatedGasWithCallbackGasLimit.toString());
    console.log("Actual gas used:", txReceipt!.gasUsed.toString());

    expect(estimatedGas).to.be.equal(txReceipt!.gasUsed);

    // Verify logs and request results
    const iface = BlocklockSender__factory.createInterface();
    const [, , ,] = extractSingleLog(
      iface,
      txReceipt!,
      await blocklockSender.getAddress(),
      iface.getEvent("BlocklockCallbackSuccess"),
    );

    blocklockRequestStatus = await blocklockSender.getRequest(1n);
    expect(blocklockRequestStatus!.condition).to.equal(encodedCondition);
    expect(blocklockRequestStatus?.decryptionKey).to.not.equal(undefined);
    expect(blocklockRequestStatus?.decryptionKey.length).to.equal(66);
    expect(await mockBlocklockReceiverInstance.plainTextValue()).to.equal(BigInt(msg));
  });

  it("can request blocklock decryption with direct funding from user contract and decrypt on-chain using filecoin gas units", async () => {
    // The ratio of Ethereum gas to Filecoin gas is about 1:444. Expect Filecoin gas numbers to look much larger than those in Ethereum.
    // https://docs.filecoin.io/smart-contracts/filecoin-evm-runtime/difference-with-ethereum

    // Buffer of 444 causes the tx gas limit to exceed block gas limit in hardhat test and reverts
    const filecoinGasBuffer = 44;

    /** Smart Contract Deployments */
    // deploy signature scheme address provider
    const SignatureSchemeAddressProvider = new ethers.ContractFactory(
      SignatureSchemeAddressProvider__factory.abi,
      SignatureSchemeAddressProvider__factory.bytecode,
      wallet,
    );
    const signatureSchemeAddressProvider = await SignatureSchemeAddressProvider.deploy(await wallet.getAddress());
    await signatureSchemeAddressProvider.waitForDeployment();
    const schemeProviderAddr = await signatureSchemeAddressProvider.getAddress();

    // deploy blocklock scheme
    const BlocklockScheme = new ethers.ContractFactory(
      BlocklockSignatureScheme__factory.abi,
      BlocklockSignatureScheme__factory.bytecode,
      wallet,
    );
    const blocklockScheme = await BlocklockScheme.deploy(
      [blocklock_default_pk.x.c0, blocklock_default_pk.x.c1],
      [blocklock_default_pk.y.c0, blocklock_default_pk.y.c1],
    );
    await blocklockScheme.waitForDeployment();
    const schemeProviderContract = SignatureSchemeAddressProvider__factory.connect(schemeProviderAddr, wallet);
    await schemeProviderContract.updateSignatureScheme(SCHEME_ID, await blocklockScheme.getAddress());
    // deploy decryption sender
    const DecryptionSender = new ethers.ContractFactory(
      DecryptionSender__factory.abi,
      DecryptionSender__factory.bytecode,
      wallet,
    );
    const decryptionSenderImplementation = await DecryptionSender.deploy();
    await decryptionSenderImplementation.waitForDeployment();
    let UUPSProxy = new ethers.ContractFactory(UUPSProxy__factory.abi, UUPSProxy__factory.bytecode, wallet);
    const uupsProxy = await UUPSProxy.deploy(
      await decryptionSenderImplementation.getAddress(),
      DecryptionSender.interface.encodeFunctionData("initialize", [await wallet.getAddress(), schemeProviderAddr]),
    );
    await uupsProxy.waitForDeployment();
    const decryptionSender = DecryptionSender.attach(await uupsProxy.getAddress());
    const decryptionSenderInstance = DecryptionSender__factory.connect(await decryptionSender.getAddress(), wallet);
    // deploy blocklock sender
    const BlocklockSender = new ethers.ContractFactory(
      BlocklockSender__factory.abi,
      BlocklockSender__factory.bytecode,
      wallet,
    );
    const blocklockSenderImplementation = await BlocklockSender.deploy();
    await blocklockSenderImplementation.waitForDeployment();
    const uupsProxy2 = await UUPSProxy.deploy(
      await blocklockSenderImplementation.getAddress(),
      BlocklockSender.interface.encodeFunctionData("initialize", [
        await wallet.getAddress(),
        await decryptionSender.getAddress(),
      ]),
    );
    await uupsProxy2.waitForDeployment();

    const blocklockSender = BlocklockSender__factory.connect(await uupsProxy2.getAddress(), wallet);

    // configure request fees parameters
    const maxGasLimit = 500_000 * filecoinGasBuffer;
    const gasAfterPaymentCalculation = 400_000 * filecoinGasBuffer;
    const fulfillmentFlatFeeNativePPM = 1_000_000;
    const weiPerUnitGas = 3_000_000;
    const blsPairingCheckOverhead = 800_000 * filecoinGasBuffer;
    const nativePremiumPercentage = 10;
    const gasForCallExactCheck = 5_000 * filecoinGasBuffer;

    await blocklockSender
      .connect(wallet)
      .setConfig(
        maxGasLimit,
        gasAfterPaymentCalculation,
        fulfillmentFlatFeeNativePPM,
        weiPerUnitGas,
        blsPairingCheckOverhead,
        nativePremiumPercentage,
        gasForCallExactCheck,
      );

    // deploy user mock decryption receiver contract
    const MockBlocklockReceiver = new ethers.ContractFactory(
      MockBlocklockReceiver__factory.abi,
      MockBlocklockReceiver__factory.bytecode,
      wallet,
    );
    const mockBlocklockReceiver = await MockBlocklockReceiver.deploy(await blocklockSender.getAddress());
    await mockBlocklockReceiver.waitForDeployment();

    /** Blocklock js Integration */
    // User or client side
    const mockBlocklockReceiverInstance = MockBlocklockReceiver__factory.connect(
      await mockBlocklockReceiver.getAddress(),
      wallet,
    );
    expect(await mockBlocklockReceiverInstance.plainTextValue()).to.equal(BigInt(0));

    const blockHeight = BigInt((await ethers.provider.getBlockNumber()) + 10);
    console.log("block height", blockHeight);

    // condition bytes
    const types = ["string", "uint256"]; // "B" is a string, and blockHeight is a uint256
    const values = ["B", blockHeight];
    const encodedCondition = ethers.AbiCoder.defaultAbiCoder().encode(types, values);
    console.log(values, encodedCondition);

    // identity for IBE
    // encrypt_towards_identity_g1 expects a uint8Array as input for the identity
    const identity = getBytes(encodedCondition);

    // message bytes
    const msg = ethers.parseEther("3"); // BigInt for 3 ETH
    const msgBytes = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);

    // generate Ciphertext
    const ct = encrypt_towards_identity_g1(encodedMessage, identity, blocklock_default_pk, BLOCKLOCK_IBE_OPTS);

    // make direct funding request with enough callbackGasLimit to cover BLS operations in call to decrypt() function
    // in receiver contract
    // for filecoin simulation test, the tx goes through if we also increase callback gas limit by buffer or not
    const callbackGasLimit = 500_000 * filecoinGasBuffer;

    let tx = await mockBlocklockReceiverInstance
      .connect(wallet)
      .createTimelockRequestWithDirectFunding(callbackGasLimit, encodedCondition, encodeCiphertextToSolidity(ct), {
        value: ethers.parseEther("2")
      });

    let receipt = await tx.wait(1);
    if (!receipt) {
      throw new Error("transaction has not been mined");
    }
    // Blocklock agent or server side
    const blockRequest = await blocklockSender.getRequest(1n);
    expect(blockRequest!.condition).to.equal(encodedCondition);

    let blocklockRequestStatus = await blocklockSender.getRequest(1n);
    console.log(blocklockRequestStatus!.condition);
    expect(blocklockRequestStatus!.condition).to.equal(encodedCondition);
    expect(blocklockRequestStatus?.decryptionKey.length).to.equal(2);

    const decryptionSenderIface = DecryptionSender__factory.createInterface();
    const [requestID, callback, schemeID, condition, ciphertext] = extractSingleLog(
      decryptionSenderIface,
      receipt,
      await decryptionSender.getAddress(),
      decryptionSenderIface.getEvent("DecryptionRequested"),
    );
    console.log(`received decryption request id ${requestID}`);
    console.log(`blocklock request id ${blockRequest?.decryptionRequestId}`);
    console.log(`callback address ${callback}, scheme id ${schemeID}`);
    const bls = await BlsBn254.create();
    const { pubKey, secretKey } = bls.createKeyPair(blsKey as `0x${string}`);

    const pubKeySerialised = serialiseG2Point(pubKey);
    expect(pubKeySerialised[0]).to.equal(blocklock_default_pk.x.c0);
    expect(pubKeySerialised[1]).to.equal(blocklock_default_pk.x.c1);
    expect(pubKeySerialised[2]).to.equal(blocklock_default_pk.y.c0);
    expect(pubKeySerialised[3]).to.equal(blocklock_default_pk.y.c1);

    const conditionBytes = isHexString(condition) ? getBytes(condition) : toUtf8Bytes(condition);

    const m = bls.hashToPoint(BLOCKLOCK_IBE_OPTS.dsts.H1_G1, conditionBytes);
    const parsedCiphertext = parseSolidityCiphertextString(ciphertext);
    console.log("Ciphertext", parsedCiphertext.U, toHexString(parsedCiphertext.V), toHexString(parsedCiphertext.W));
    const signature = bls.sign(m, secretKey).signature;
    const sig = bls.serialiseG1Point(signature);
    const sigBytes = AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [sig[0], sig[1]]);
    console.log("signature", sigBytes);
    const decryption_key = preprocess_decryption_key_g1(parsedCiphertext, { x: sig[0], y: sig[1] }, BLOCKLOCK_IBE_OPTS);
    console.log("decryption key", toHexString(decryption_key));

    // fulfill the conditional encryption request if profitable
    const estimatedGas = await decryptionSenderInstance
      .connect(wallet)
      .fulfillDecryptionRequest.estimateGas(requestID, decryption_key, sigBytes);
    const estimatedGasWithCallbackGasLimit = BigInt(estimatedGas) + BigInt(callbackGasLimit);

    // Fetch current gas pricing (EIP-1559 compatible)
    const feeData = await wallet.provider.getFeeData();
    const maxFeePerGas = feeData.maxFeePerGas!;
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!;
    const userPayment = blocklockRequestStatus.directFundingFeePaid;

    const baseFeePerGas = (await wallet.provider.getBlock("latest"))?.baseFeePerGas!;
    const effectiveGasPrice =
      maxFeePerGas < baseFeePerGas + maxPriorityFeePerGas ? maxFeePerGas : baseFeePerGas + maxPriorityFeePerGas;

    // Calculate if it's profitable to execute without buffer
    let expectedTxCost = estimatedGasWithCallbackGasLimit * effectiveGasPrice;
    let profitAfterTx = BigInt(userPayment) - BigInt(expectedTxCost);

    // Define the minimum profit margin threshold (e.g., 10%)
    const profitThresholdPercent = 10n;

    // Compute profit percentage
    let profitPercent = (profitAfterTx * 100n) / BigInt(userPayment);

    // Expect profit to meet or exceed the threshold
    expect(profitPercent).to.be.gte(profitThresholdPercent);

    // Calculate if it's profitable to execute with buffer
    // It is best to calculate if it's profitable to execute with buffer
    // as in some scenarios or chains, the transaction could fail without adding the buffer if the actual gas used is
    // higher than the estimatedGasWithCallbackGasLimit.
    // It is also safer to add a buffer to the estimatedGasWithCallbackGasLimit, not just estimatedGas
    const gasBuffer = (estimatedGasWithCallbackGasLimit * 120n) / 100n; // 20% buffer
    expectedTxCost = gasBuffer * effectiveGasPrice;
    profitAfterTx = BigInt(userPayment) - BigInt(expectedTxCost);

    // Compute profit percentage
    profitPercent = (profitAfterTx * 100n) / BigInt(userPayment);

    // Expect profit to meet or exceed the threshold
    expect(profitPercent).to.be.gte(profitThresholdPercent);

    // transaction passes whether we add buffer to the gas limit or don't
    // because the actual gas used == estimated gas without callback gas limit
    tx = await decryptionSenderInstance.connect(wallet).fulfillDecryptionRequest(requestID, decryption_key, sigBytes, {
      gasLimit: gasBuffer,
      maxFeePerGas,
      maxPriorityFeePerGas,
    });
    const [success, txReceipt] = await checkTxMined(tx.hash, wallet.provider);
    expect(success).to.be.equal(true);

    console.log("Estimated gas:", estimatedGas.toString());
    console.log("Callback gas limit:", callbackGasLimit.toString());
    console.log("Estimated gas + Callback gas limit:", estimatedGasWithCallbackGasLimit.toString());
    console.log("Actual gas used:", txReceipt!.gasUsed.toString());

    expect(estimatedGas).to.be.equal(txReceipt!.gasUsed);

    // Verify logs and request results
    const iface = BlocklockSender__factory.createInterface();
    const [, , ,] = extractSingleLog(
      iface,
      txReceipt!,
      await blocklockSender.getAddress(),
      iface.getEvent("BlocklockCallbackSuccess"),
    );

    blocklockRequestStatus = await blocklockSender.getRequest(1n);
    expect(blocklockRequestStatus!.condition).to.equal(encodedCondition);
    expect(blocklockRequestStatus?.decryptionKey).to.not.equal(undefined);
    expect(blocklockRequestStatus?.decryptionKey.length).to.equal(66);
    expect(await mockBlocklockReceiverInstance.plainTextValue()).to.equal(BigInt(msg));
  });
});

async function checkTxMined(txHash: string, provider: Provider): Promise<[boolean, TransactionReceipt | null]> {
  const receipt = await provider.getTransactionReceipt(txHash);

  if (!receipt) {
    console.log("Transaction not mined yet.");
    return [false, null];
  }

  if (receipt.status === 1) {
    console.log("Transaction mined and succeeded.");
    return [true, receipt];
  } else {
    console.log("Transaction mined but failed.");
    return [false, receipt];
  }
}

function toHexString(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
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

// returns the first instance of an event log from a transaction receipt that matches the address provided
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

function uint8ArrayToHexString(uint8: Uint8Array): string {
  return (
    "0x" +
    Array.from(uint8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}
