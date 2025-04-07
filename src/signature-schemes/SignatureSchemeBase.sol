// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {BLS} from "../libraries/BLS.sol";

abstract contract SignautreSchemeBase {
    // fixme uncomment code
    // Link public keys of threshold network statically to signature scheme contracts and remove from constructor of sender contracts. Admin cannot update, simply use new scheme id.
    BLS.PointG2 private publicKey = BLS.PointG2({x: [uint256(0), uint256(0)], y: [uint256(0), uint256(0)]});

    constructor(uint256[2] memory x, uint256[2] memory y) {
        publicKey = BLS.PointG2({x: x, y: y});
    }
}
