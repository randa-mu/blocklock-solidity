import { BlsBn254, serialiseG2Point } from "../../../scripts/crypto";

const { expect } = require("chai");

describe("bls-bn254", () => {
  it("can turn hex into a g2 point", async () => {
    const publicKey =
      "0xcaf65381e7d3d3379164abb88f94ee5675c748b8a0113987fa0b38cc9ed39126bf3702fdc4f4572f0260ffebe969a0165e401fb361508a1098b025510ae26328";
    const bls = await BlsBn254.create();
    const point = bls.g2From(publicKey);
    expect(point.isZero()).to.be.equal(false);
  });
  it("turns into the right 4 bigints", async () => {
    const publicKey =
      "0xcaf65381e7d3d3379164abb88f94ee5675c748b8a0113987fa0b38cc9ed39126bf3702fdc4f4572f0260ffebe969a0165e401fb361508a1098b025510ae26328";
    const bls = await BlsBn254.create();
    const point = bls.g2From(publicKey);
    const expectedPK: [bigint, bigint, bigint, bigint] = [
      17445541620214498517833872661220947475697073327136585274784354247720096233162n,
      18268991875563357240413244408004758684187086817233527689475815128036446189503n,
      11401601170172090472795479479864222172123705188644469125048759621824127399516n,
      8044854403167346152897273335539146380878155193886184396711544300199836788154n,
    ];

    expect(serialiseG2Point(point)).to.deep.equal(expectedPK);
  });
});
