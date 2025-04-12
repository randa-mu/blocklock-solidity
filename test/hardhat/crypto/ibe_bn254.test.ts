import {
  decrypt_g1,
  decrypt_g1_with_preprocess,
  deserializeCiphertext,
  encrypt_towards_identity_g1,
  get_identity_g1,
  preprocess_decryption_key_g1,
  serializeCiphertext,
  DEFAULT_OPTS
} from "../../../utils/crypto";
import { bn254 } from "../../../utils/crypto/bn254";
import { ethers, getBytes, AbiCoder, hexlify } from "ethers";

const { expect } = require("chai");

describe("ibe bn254", () => {
  it("consistency", async () => {
    const m = new Uint8Array(Buffer.from("IBE BN254 Consistency Test"));
    const identity = Buffer.from("TEST");
    const identity_g1 = bn254.G1.ProjectivePoint.fromAffine(await get_identity_g1(identity));

    const x = bn254.G1.normPrivateKeyToScalar(bn254.utils.randomPrivateKey());
    const X_G2 = bn254.G2.ProjectivePoint.BASE.multiply(x).toAffine();
    const sig = identity_g1.multiply(x).toAffine();

    const ct = await encrypt_towards_identity_g1(m, identity, X_G2);
    const m2 = await decrypt_g1(ct, sig);
    expect(m).to.deep.equal(m2);
  });

  it("consistency in processing ethers encoded uint", async () => {
      const msg = ethers.parseEther("4");
    const msgBytes = AbiCoder.defaultAbiCoder().encode(["uint256"], [msg]);
    const encodedMessage = getBytes(msgBytes);

    const m = encodedMessage; //new Uint8Array(Buffer.from("IBE BN254 Consistency Test"));
    const identity = Buffer.from("13") // Buffer.from("TEST");
    const identity_g1 = bn254.G1.ProjectivePoint.fromAffine(await get_identity_g1(identity));

    const x = bn254.G1.normPrivateKeyToScalar(bn254.utils.randomPrivateKey());
    const X_G2 = bn254.G2.ProjectivePoint.BASE.multiply(x).toAffine();
    const sig = identity_g1.multiply(x).toAffine();

    const ct = await encrypt_towards_identity_g1(m, identity, X_G2);
    const m2 = await decrypt_g1(ct, sig);
    expect(m).to.deep.equal(m2);
  });

  it("consistency with preprocessing", async () => {
    const m = new Uint8Array(Buffer.from("IBE BN254 Consistency Test"));
    const identity = Buffer.from("TEST");
    const identity_g1 = bn254.G1.ProjectivePoint.fromAffine(await get_identity_g1(identity));

    const x = bn254.G1.normPrivateKeyToScalar(bn254.utils.randomPrivateKey());
    const X_G2 = bn254.G2.ProjectivePoint.BASE.multiply(x).toAffine();
    const sig = identity_g1.multiply(x).toAffine();

    const ct = await encrypt_towards_identity_g1(m, identity, X_G2);
    const decryption_key = await preprocess_decryption_key_g1(ct, sig);

    const m2 = decrypt_g1_with_preprocess(ct, decryption_key);

    expect(m).to.deep.equal(m2);
  });

  it("serialization", async () => {
    const m = new Uint8Array(Buffer.from("IBE BN254 Serialization Test"));
    const identity = Buffer.from("TEST");

    const x = bn254.G1.normPrivateKeyToScalar(bn254.utils.randomPrivateKey());
    const X_G2 = bn254.G2.ProjectivePoint.BASE.multiply(x).toAffine();

    const ct = await encrypt_towards_identity_g1(m, identity, X_G2);

    const serCt = serializeCiphertext(ct);
    const deserCt = deserializeCiphertext(serCt);
    expect(ct).to.deep.equal(deserCt);
  });
});
