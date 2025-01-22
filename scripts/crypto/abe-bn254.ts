/**
 * Conditional Encryption / Attribute-Based Encryption for marshmallow
 */

import { encrypt_towards_identity_g1, G1, G2, get_identity_g1, serializeCiphertext } from "./ibe-bn254"

export type Conditions = {
    blockHeight: bigint
}

/**
 * Encrypt a message such that it can only be decrypted once various conditions are satisfied.
 * @param message byte array to encrypt
 * @param conditions various conditions / attributes upon which the ciphertext can be decrypted
 * @param pk public key of the committee
 * @returns encrypted message
 */
export function encryptWithConditions(message: Uint8Array, conditions: Conditions, pk: G2): Uint8Array {
    const identity = identityFromConditions(conditions)
    const ciphertext = encrypt_towards_identity_g1(message, identity, pk)
    return serializeCiphertext(ciphertext)
}

/**
 * Obtain an identity on BN254 G1 from the conditions.
 * @param conditions various conditions / attributes required to create the identity
 * @returns identity representing the conditions
 */
export function identityG1FromConditions(conditions: Conditions): G1 {
    const encodedConditions = encodeConditions(conditions)
    const identity = identityFromEncodedConditions(encodedConditions)
    return get_identity_g1(identity)
}

/**
 * Obtain an identity on BN254 G1 from the encoded conditions.
 * @param conditions various conditions / attributes required to create the identity
 * @returns identity representing the conditions
 */
export function identityG1FromEncodedConditions(encodedConditions: Uint8Array): G1 {
    const identity = identityFromEncodedConditions(encodedConditions)
    return get_identity_g1(identity)
}

/**
 * Obtain an identity as a byte array from the conditions.
 * @param conditions various conditions / attributes required to create the identity
 * @returns identity representing the conditions
 */
export function identityFromConditions(conditions: Conditions): Uint8Array {
    const encodedConditions = encodeConditions(conditions)
    return identityFromEncodedConditions(encodedConditions)
}

/**
 * Obtain an identity as a byte array from the encoded conditions.
 * @param conditions various conditions / attributes required to create the identity
 * @returns identity representing the conditions
 */
function identityFromEncodedConditions(encodedConditions: Uint8Array): Uint8Array {
    const identity = new Uint8Array(encodedConditions.length)
    identity.set(encodedConditions)
    return identity
}

/**
 * Encode the conditions into a byte array
 * @param conditions various conditions / attributes required for the decryption of the ciphertext
 * @returns encoded conditions as a byte array
 */
export function encodeConditions(conditions: Conditions): Uint8Array {
    const encodedBlockHeight = blockHeightToBEBytes(conditions.blockHeight)
    return encodedBlockHeight
}

function blockHeightToBEBytes(blockHeight: bigint) {
    // Assume a block height < 2**64
    const buffer = new ArrayBuffer(8)
    const dataView = new DataView(buffer)
    dataView.setBigUint64(0, blockHeight)

    return new Uint8Array(buffer)
}
