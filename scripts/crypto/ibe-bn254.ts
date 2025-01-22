import { Buffer as BufferPolyfill } from 'buffer'
declare let Buffer: typeof BufferPolyfill
globalThis.Buffer = BufferPolyfill

import * as asn1js from "asn1js"
import { bn254, htfDefaultsG1, mapToG1 } from './bn254'
import { xor } from './utils'
import { Fp, Fp12, Fp2 } from '@noble/curves/abstract/tower'
import { AffinePoint } from '@noble/curves/abstract/weierstrass'
import { createHasher, expand_message_xmd, expand_message_xof, hash_to_field } from "@noble/curves/abstract/hash-to-curve"
import { CHash } from "@noble/curves/abstract/utils"
import { keccak_256 } from "@noble/hashes/sha3"

export type G1 = AffinePoint<Fp>
export type G2 = AffinePoint<Fp2>
export type GT = Fp12

export interface Ciphertext {
    U: G2,
    V: Uint8Array
    W: Uint8Array
}

// Various options used to customize the IBE scheme
export type IbeOpts = {
    hash: CHash,                // hash function
    k: number,                  // k-bit collision resistance of hash
    expand_fn: 'xmd' | 'xof',   // "xmd": expand_message_xmd, "xof": expand_message_xof, see RFC9380, Section 5.3.
    dsts: DstOpts,
}

// Various DSTs used throughout the IBE scheme
export type DstOpts = {
    H1_G1: Uint8Array,
    H2: Uint8Array,
    H3: Uint8Array,
    H4: Uint8Array,
}

// Default IBE options.
export const DEFAULT_OPTS: IbeOpts = {
    hash: keccak_256,
    k: 128,
    expand_fn: 'xmd',
    dsts: {
        H1_G1: Buffer.from('IBE_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_'),
        H2: Buffer.from('IBE_BN254_XMD:KECCAK-256_H2_'),
        H3: Buffer.from('IBE_BN254_XMD:KECCAK-256_H3_'),
        H4: Buffer.from('IBE_BN254_XMD:KECCAK-256_H4_'),
    }
}

/*
 * Convert the identity into a point on the curve.
 */
export function get_identity_g1(identity: Uint8Array, opts: IbeOpts = DEFAULT_OPTS): G1 {
    return hash_identity_to_point_g1(identity, opts)
}

/*
 * Encryption function for IBE based on https://www.iacr.org/archive/crypto2001/21390212.pdf Section 6 / https://eprint.iacr.org/2023/189.pdf, Algorithm 1
 * with the identity on G1, and the master public key on G2.
 */
export function encrypt_towards_identity_g1(m: Uint8Array, identity: Uint8Array, pk_g2: G2, opts: IbeOpts = DEFAULT_OPTS): Ciphertext {
    if (m.length > opts.hash.outputLen) {
        throw new Error(`cannot encrypt messages larger than our hash output: ${opts.hash.outputLen} bytes.`)
    }

    // \ell = min(len(m), opts.hash.outputLen)
    const ell_bytes = m.length

    // Compute the identity's public key on G1
    // 3: PK_\rho \gets e(H_1(\rho), P)
    const identity_g1 = hash_identity_to_point_g1(identity, opts)
    const identity_g1p = bn254.G1.ProjectivePoint.fromAffine(identity_g1)
    const pk_g2p = bn254.G2.ProjectivePoint.fromAffine(pk_g2)
    const pk_rho = bn254.pairing(identity_g1p, pk_g2p)

    // Sample a one-time key
    // 4: \sigma \getsr \{0,1\}^\ell
    const sigma = new Uint8Array(32);
    crypto.getRandomValues(sigma)

    // Derive an ephemeral keypair
    // 5: r \gets H_3(\sigma, M)
    const r = hash_sigma_m_to_field(sigma, m, opts)
    // 6: U \gets [r]G_2
    const u_g2 = bn254.G2.ProjectivePoint.BASE.multiply(r).toAffine()

    // Hide the one-time key
    // 7: V \gets \sigma \xor H_2((PK_\rho)^r)
    const shared_key = bn254.fields.Fp12.pow(pk_rho, r)
    const v = xor(sigma, hash_shared_key_to_bytes(shared_key, sigma.length, opts))

    // Encrypt message m with one-time-pad derived from \sigma
    // 8: W \gets M \xor H_4(\sigma)
    const w = xor(m, hash_sigma_to_bytes(sigma, ell_bytes, opts))

    // 9: return ciphertext
    return {
        U: u_g2,
        V: v,
        W: w
    }
}

/*
 * Decryption function for IBE based on https://www.iacr.org/archive/crypto2001/21390212.pdf Section 6 / https://eprint.iacr.org/2023/189.pdf, Algorithm 1
 * with the identity on G1, and the master public key on G2.
 */
export function decrypt_g1(ciphertext: Ciphertext, decryption_key_g1: G1, opts: IbeOpts = DEFAULT_OPTS): Uint8Array {
    // Get the one-time decryption key
    const key = preprocess_decryption_key_g1(ciphertext, decryption_key_g1, opts)
    return decrypt_g1_with_preprocess(ciphertext, key, opts)
}

/**
 * Decryption function for IBE based on https://www.iacr.org/archive/crypto2001/21390212.pdf Section 6 / https://eprint.iacr.org/2023/189.pdf, Algorithm 1
 * with the identity on G1, and the master public key on G2.
 */
export function decrypt_g1_with_preprocess(ciphertext: Ciphertext, preprocessed_decryption_key: Uint8Array, opts: IbeOpts = DEFAULT_OPTS): Uint8Array {
    // Check well-formedness of the ciphertext
    if (ciphertext.W.length > opts.hash.outputLen) {
        throw new Error(`cannot decrypt messages larger than our hash output: ${opts.hash.outputLen} bytes.`)
    }
    if (ciphertext.V.length !== opts.hash.outputLen) {
        throw new Error(`cannot decrypt encryption key of invalid length != ${opts.hash.outputLen} bytes.`)
    }
    if (ciphertext.V.length !== preprocessed_decryption_key.length) {
        throw new Error(`preprocessed decryption key of invalid length`)
    }

    // \ell = min(len(w), opts.hash.outputLen)
    const ell_bytes = ciphertext.W.length

    // Get the one-time decryption key
    // 3: \sigma' \gets V \xor H_2(e(\pi_\rho, U))
    const sigma2 = xor(ciphertext.V, preprocessed_decryption_key)

    // Decrypt the message
    // 4: M' \gets W \xor H_4(\sigma')
    const m2 = xor(ciphertext.W, hash_sigma_to_bytes(sigma2, ell_bytes, opts))

    // Derive the ephemeral keypair with the candidate \sigma'
    // 5: r \gets H_3(\sigma, M)
    const r = hash_sigma_m_to_field(sigma2, m2, opts)

    // Verify that \sigma' is consistent with the message and ephemeral public key
    // 6: if U = [r]G_2 then return M' else return \bot
    const u_g2 = bn254.G2.ProjectivePoint.BASE.multiply(r)
    if (bn254.G2.ProjectivePoint.fromAffine(ciphertext.U).equals(u_g2)) {
        return m2
    } else {
        throw new Error("invalid proof: rP check failed")
    }
}

/**
 * Preprocess a signature by computing the hash of the pairing, i.e.,
 * H_2(e(\pi_\rho, U)).
 * @param ciphertext ciphertext to preprocess the decryption key for
 * @param decryption_key_g1 decryption key on g1 for the ciphertext
 * @param opts IBE scheme options
 * @returns preprocessed decryption key
 */
export function preprocess_decryption_key_g1(ciphertext: Ciphertext, decryption_key_g1: G1, opts: IbeOpts = DEFAULT_OPTS): Uint8Array {
    const u_g2p = bn254.G2.ProjectivePoint.fromAffine(ciphertext.U)
    u_g2p.assertValidity() // throws an error if point is invalid

    // Derive the shared key using the decryption key and the ciphertext's ephemeral public key
    const decryption_key_g1p = bn254.G1.ProjectivePoint.fromAffine(decryption_key_g1)
    const shared_key = bn254.pairing(decryption_key_g1p, u_g2p)

    // Return the mask H_2(e(\pi_\rho, U))
    return hash_shared_key_to_bytes(shared_key, ciphertext.V.length, opts)
}

/**
 * Serialize Ciphertext to ASN.1 structure
 * Ciphertext ::= SEQUENCE {
 *    u SEQUENCE {
 *        x SEQUENCE {
 *            c0 INTEGER,
 *            c1 INTEGER
 *        },
 *        y SEQUENCE {
 *            c0 INTEGER,
 *            c1 INTEGER
 *        }
 *    },
 *    v OCTET STRING,
 *    w OCTET STRING
 * }
 */
export function serializeCiphertext(ct: Ciphertext): Uint8Array {
    const sequence = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({
                value: [
                    new asn1js.Sequence({
                        value: [
                            asn1js.Integer.fromBigInt(ct.U.x.c0),
                            asn1js.Integer.fromBigInt(ct.U.x.c1),
                        ]
                    }),
                    new asn1js.Sequence({
                        value: [
                            asn1js.Integer.fromBigInt(ct.U.y.c0),
                            asn1js.Integer.fromBigInt(ct.U.y.c1),
                        ]
                    }),
                ]
            }),
            new asn1js.OctetString({ valueHex: ct.V }),
            new asn1js.OctetString({ valueHex: ct.W }),
        ],
    });

    return new Uint8Array(sequence.toBER())
}

export function deserializeCiphertext(ct: Uint8Array): Ciphertext {
    const schema = new asn1js.Sequence({
        name: "ciphertext",
        value: [
            new asn1js.Sequence({
                name: "U",
                value: [
                    new asn1js.Sequence({
                        name: "x",
                        value: [
                            new asn1js.Integer(),
                            new asn1js.Integer(),
                        ]
                    }),
                    new asn1js.Sequence({
                        name: "y",
                        value: [
                            new asn1js.Integer(),
                            new asn1js.Integer(),
                        ]
                    }),
                ]
            }),
            new asn1js.OctetString({ name: "V" }),
            new asn1js.OctetString({ name: "W" }),
        ],
    });

    // Verify the validity of the schema
    const res = asn1js.verifySchema(ct, schema)
    if (!res.verified) {
        throw new Error("invalid ciphertext")
    }

    const V = new Uint8Array(res.result['V'].valueBlock.valueHex)
    const W = new Uint8Array(res.result['W'].valueBlock.valueHex)

    function bytesToBigInt(bytes: ArrayBuffer) {
        const byteArray = Array.from(new Uint8Array(bytes))
        const hex: string = byteArray.map(e => e.toString(16).padStart(2, '0')).join('')
        return BigInt('0x' + hex)
    }
    const x = bn254.fields.Fp2.create({
        c0: bytesToBigInt(res.result['x'].valueBlock.value[0].valueBlock.valueHex),
        c1: bytesToBigInt(res.result['x'].valueBlock.value[1].valueBlock.valueHex),
    })
    const y = bn254.fields.Fp2.create({
        c0: bytesToBigInt(res.result['y'].valueBlock.value[0].valueBlock.valueHex),
        c1: bytesToBigInt(res.result['y'].valueBlock.value[1].valueBlock.valueHex),
    })
    const U = { x, y }

    return {
        U,
        V,
        W,
    }
}

// Concrete instantiation of H_1 that outputs a point on G1
// H_1: \{0, 1\}^\ast \rightarrow G_1
function hash_identity_to_point_g1(identity: Uint8Array, opts: IbeOpts): G1 {
    const hasher = createHasher(bn254.G1.ProjectivePoint, mapToG1, {
        p: htfDefaultsG1.p,
        m: htfDefaultsG1.m,
        hash: opts.hash,
        k: opts.k,
        DST: opts.dsts.H1_G1,
        expand: opts.expand_fn,
    })
    return hasher.hashToCurve(identity).toAffine()
}

// Concrete instantiation of H_2 that outputs a uniformly random byte string of length n
// H_2: G_T \rightarrow \{0, 1\}^\ell
function hash_shared_key_to_bytes(shared_key: GT, n: number, opts: IbeOpts): Uint8Array {
    // todo: analyse the format of Fp12.to_bytes()
    if (opts.expand_fn == "xmd") {
        return expand_message_xmd(bn254.fields.Fp12.toBytes(shared_key), opts.dsts.H2, n, opts.hash)
    } else {
        return expand_message_xof(bn254.fields.Fp12.toBytes(shared_key), opts.dsts.H2, n, opts.k, opts.hash)
    }
}

// Concrete instantiation of H_3 that outputs a point in Fp
// H_3: \{0, 1\}^\ell \times \{0, 1\}^\ell \rightarrow Fp
function hash_sigma_m_to_field(sigma: Uint8Array, m: Uint8Array, opts: IbeOpts): bigint {
    // input = \sigma || m
    const input = new Uint8Array(sigma.length + m.length)
    input.set(sigma)
    input.set(m, sigma.length)

    // hash_to_field(\sigma || m)
    return hash_to_field(input, 1, {
        p: htfDefaultsG1.p,
        m: htfDefaultsG1.m,
        hash: opts.hash,
        k: opts.k,
        DST: opts.dsts.H3,
        expand: opts.expand_fn,
    })[0][0];
}

// Concrete instantiation of H_4 that outputs a uniformly random byte string of length n
// H_4: \{0, 1\}^\ell \rightarrow \{0, 1\}^\ell
function hash_sigma_to_bytes(sigma: Uint8Array, n: number, opts: IbeOpts): Uint8Array {
    if (opts.expand_fn == "xmd") {
        return expand_message_xmd(sigma, opts.dsts.H4, n, opts.hash)
    } else {
        return expand_message_xof(sigma, opts.dsts.H4, n, opts.k, opts.hash)
    }
}
