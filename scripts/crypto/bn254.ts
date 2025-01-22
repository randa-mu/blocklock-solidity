import { bn254 as _bn254 } from "@noble/curves/bn254"
import { psiFrobenius } from "@noble/curves/abstract/tower"
import { BasicWCurve } from "@noble/curves/abstract/weierstrass"
import { validateField, FpIsSquare } from "@noble/curves/abstract/modular"
import { keccak_256 } from "@noble/hashes/sha3"
import { randomBytes } from "@noble/hashes/utils"
import { bls, CurveFn } from "@noble/curves/abstract/bls"

// seed used by the cofactor clearing on G2
const SEED = BigInt("4965661367192848881")

// Create a SVDW mapping with constant parameters for G1
const G1_SVDW = mapToCurveSVDW(_bn254.G1.CURVE, {
    // Z = 1 satisfies the conditions described in https://datatracker.ietf.org/doc/html/rfc9380#svdw
    z: _bn254.G1.CURVE.Fp.ONE,
    // c1, c2, c3, c4 are the SvdW constants described in https://datatracker.ietf.org/doc/html/rfc9380#straightline-svdw
    // c1 = g(Z)
    c1: _bn254.G1.CURVE.Fp.create(
        BigInt(4)
    ),
    // c2 = -Z / 2
    c2: _bn254.G1.CURVE.Fp.create(
        BigInt(
            '10944121435919637611123202872628637544348155578648911831344518947322613104291'
        )
    ),
    // c3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A))     # sgn0(c3) MUST equal 0
    c3: _bn254.G1.CURVE.Fp.create(
        BigInt(
            '8815841940592487685674414971303048083897117035520822607866'
        )
    ),
    // c4 = -4 * g(Z) / (3 * Z^2 + 4 * A)
    c4: _bn254.G1.CURVE.Fp.create(
        BigInt(
            '7296080957279758407415468581752425029565437052432607887563012631548408736189'
        )
    ),
});

// Create a SVDW mapping with constant parameters for G2
const G2_SVDW = mapToCurveSVDW(_bn254.G2.CURVE, {
    // Z = 1 satisfies the conditions described in https://datatracker.ietf.org/doc/html/rfc9380#svdw
    z: _bn254.G2.CURVE.Fp.ONE,
    // c1, c2, c3, c4 are the SvdW constants described in https://datatracker.ietf.org/doc/html/rfc9380#straightline-svdw
    // c1 = g(Z)
    c1: _bn254.G2.CURVE.Fp.create(
        { c0: BigInt('19485874751759354771024239261021720505790618469301721065564631296452457478374'), c1: BigInt('266929791119991161246907387137283842545076965332900288569378510910307636690') }
    ),
    // c2 = -Z / 2
    c2: _bn254.G2.CURVE.Fp.create(
        { c0: BigInt('10944121435919637611123202872628637544348155578648911831344518947322613104291'), c1: BigInt(0) }
    ),
    // c3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A))     # sgn0(c3) MUST equal 0
    c3: _bn254.G2.CURVE.Fp.create(
        { c0: BigInt('18992192239972082890849143911285057164064277369389217330423471574879236301292'), c1: BigInt('21819008332247140148575583693947636719449476128975323941588917397607662637108') }
    ),
    // c4 = -4 * g(Z) / (3 * Z^2 + 4 * A)
    c4: _bn254.G2.CURVE.Fp.create(
        { c0: BigInt('10499238450719652342378357227399831140106360636427411350395554762472100376473'), c1: BigInt('6940174569119770192419592065569379906172001098655407502803841283667998553941') }
    ),
});

// Hash to field parameters for G1
export const htfDefaultsG1 = Object.freeze({
    // DST: a domain separation tag defined in section 2.2.5
    DST: 'BN254G1_XMD:KECCAK-256_SVDW_RO_',
    p: _bn254.fields.Fp.ORDER,
    m: 1,
    k: 128,
    expand: 'xmd',
    hash: keccak_256,
} as const);

// Hash to field parameters for G2
export const htfDefaultsG2 = Object.freeze({
    // DST: a domain separation tag defined in section 2.2.5
    DST: 'BN254G2_XMD:KECCAK-256_SVDW_RO_',
    p: _bn254.fields.Fp.ORDER,
    m: 2,
    k: 128,
    expand: 'xmd',
    hash: keccak_256,
} as const);

// Ψ endomorphism for BN254
const { G2psi, G2psi2, psi } = psiFrobenius(_bn254.fields.Fp, _bn254.fields.Fp2, _bn254.fields.Fp2.create({ c0: BigInt(9), c1: BigInt(1) })) // 9 + i is the nonresidue

/**
 * bn254 (a.k.a. alt_bn128) pairing-friendly curve.
 * Contains G1 / G2 operations and pairings.
 */
export const bn254: CurveFn = bls({
    // Fields
    fields: { Fp: _bn254.fields.Fp, Fp2: _bn254.fields.Fp2, Fp6: _bn254.fields.Fp6, Fp12: _bn254.fields.Fp12, Fr: _bn254.fields.Fr },
    G1: {
        ..._bn254.G1.CURVE,
        htfDefaults: htfDefaultsG1,
        ShortSignature: _bn254.ShortSignature,
        mapToCurve: (scalars: bigint[]) => {
            return G1_SVDW(_bn254.G1.CURVE.Fp.create(scalars[0]));
        },
    },
    G2: {
        ..._bn254.G2.CURVE,
        htfDefaults: htfDefaultsG2,
        mapToCurve: (scalars: bigint[]) => {
            const u = _bn254.G2.CURVE.Fp.create(
                { c0: scalars[0], c1: scalars[1] }
            )
            return G2_SVDW(u);
        },
        // Maps the point into the prime-order subgroup G2.
        /// Based on http://cacr.uwaterloo.ca/techreports/2011/cacr2011-26.pdf, 6.1
        /// Adapted from: https://github.com/nikkolasg/bn254_hash2curve/blob/5995e36149b0119fa2a97dfcc00758729f00cc93/src/hash2g2.rs#L291
        clearCofactor: (c, P) => {
            const x = SEED;
            const p0 = P.multiplyUnsafe(x);           // [x]P
            const p1 = G2psi(c, p0.add(p0.double())); // Ψ([3x]P)
            const p2 = G2psi2(c, p0);                 // Ψ²([x]P)
            const p3 = G2psi(c, G2psi2(c, P))         // Ψ³(P)
            // [x]P + Ψ([3x]P) + Ψ²([x]P) + Ψ³(P)
            return p0.add(p1.add(p2.add(p3)))
        },
        Signature: _bn254.Signature,
    },
    params: {
        ..._bn254.params,
        xNegative: false,
        twistType: 'divisive',
    },
    htfDefaults: htfDefaultsG1,
    hash: htfDefaultsG1.hash,
    randomBytes: randomBytes,

    postPrecompute: (Rx, Ry, Rz, Qx, Qy, pointAdd) => {
        const q = psi(Qx, Qy);
        ({ Rx, Ry, Rz } = pointAdd(Rx, Ry, Rz, q[0], q[1]));
        const q2 = psi(q[0], q[1]);
        pointAdd(Rx, Ry, Rz, q2[0], _bn254.fields.Fp2.neg(q2[1]));
    },
});

export function mapToG1(scalars: bigint[]) {
    return G1_SVDW(_bn254.G1.CURVE.Fp.create(scalars[0]));
}

export function mapToG2(scalars: bigint[]) {
    const u = _bn254.G2.CURVE.Fp.create(
        { c0: scalars[0], c1: scalars[1] }
    )
    return G2_SVDW(u);
}

function mapToCurveSVDW<T>(CG: BasicWCurve<T>, opts: { c1: T, c2: T, c3: T, c4: T, z: T }): (u: T) => { x: T, y: T } {
    const Fp = CG.Fp;
    const is_square = FpIsSquare(Fp);

    validateField(Fp)
    if (!Fp.isValid(CG.a) || !Fp.isValid(CG.b) || !Fp.isValid(opts.z))
        throw new Error('mapToCurveSimpleSVDW: invalid opts')
    if (!Fp.isOdd) throw new Error('Fp.isOdd is not implemented!')

    // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html#section-f.1
    //    1. c1 = g(Z)
    const c1 = Fp.create(opts.c1)
    //    2. c2 = -Z / 2
    const c2 = Fp.create(opts.c2)
    //    3. c3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A))     # sgn0(c3) MUST equal 0
    const c3 = Fp.create(opts.c3)
    //    4. c4 = -4 * g(Z) / (3 * Z^2 + 4 * A)
    const c4 = Fp.create(opts.c4)

    return (_u: T): { x: T, y: T } => {
        const u = Fp.create(_u)
        //    1.  tv1 = u^2
        let tv1 = Fp.sqr(u)
        //    2.  tv1 = tv1 * c1
        tv1 = Fp.mul(tv1, c1)
        //    3.  tv2 = 1 + tv1
        const tv2 = Fp.add(Fp.ONE, tv1)
        //    4.  tv1 = 1 - tv1
        tv1 = Fp.sub(Fp.ONE, tv1)
        //    5.  tv3 = tv1 * tv2
        let tv3 = Fp.mul(tv1, tv2)
        //    6.  tv3 = inv0(tv3)
        tv3 = Fp.inv(tv3)
        //    7.  tv4 = u * tv1
        let tv4 = Fp.mul(u, tv1)
        //    8.  tv4 = tv4 * tv3
        tv4 = Fp.mul(tv4, tv3)
        //    9.  tv4 = tv4 * c3
        tv4 = Fp.mul(tv4, c3)
        //    10.  x1 = c2 - tv4
        const x1 = Fp.sub(c2, tv4)
        //    11. gx1 = x1^2
        let gx1 = Fp.sqr(x1)
        //    12. gx1 = gx1 + A
        gx1 = Fp.add(gx1, CG.a); // a is 0 for used curves.

        //    13. gx1 = gx1 * x1
        gx1 = Fp.mul(gx1, x1)
        //    14. gx1 = gx1 + B
        gx1 = Fp.add(gx1, CG.b)

        //    15.  e1 = is_square(gx1)
        const e1 = is_square(gx1)
        //    16.  x2 = c2 + tv4
        const x2 = Fp.add(c2, tv4)
        //    17. gx2 = x2^2
        let gx2 = Fp.sqr(x2)
        //    18. gx2 = gx2 + A
        gx2 = Fp.add(gx2, CG.a); // a is 0 for used curves.

        //    19. gx2 = gx2 * x2
        gx2 = Fp.mul(gx2, x2)
        //    20. gx2 = gx2 + B
        gx2 = Fp.add(gx2, CG.b)
        //    21.  e2 = is_square(gx2) AND NOT e1
        const e2 = is_square(gx2) && !e1
        //    22.  x3 = tv2^2
        let x3 = Fp.sqr(tv2)
        //    23.  x3 = x3 * tv3
        x3 = Fp.mul(x3, tv3)
        //    24.  x3 = x3^2
        x3 = Fp.sqr(x3)
        //    25.  x3 = x3 * c4
        x3 = Fp.mul(x3, c4)
        //    26.  x3 = x3 + Z
        x3 = Fp.add(x3, opts.z)

        //    27.  x = CMOV(x3, x1, e1)      # x = x1 if gx1 is square, else x = x3
        let x = Fp.cmov(x3, x1, e1)
        //    28.  x = CMOV(x, x2, e2)       # x = x2 if gx2 is square and gx1 is not
        x = Fp.cmov(x, x2, e2)
        //    29.  gx = x^2
        let gx = Fp.sqr(x)
        //    30.  gx = gx + A
        gx = Fp.add(gx, CG.a)

        //    31.  gx = gx * x
        gx = Fp.mul(gx, x)
        //    32.  gx = gx + B
        gx = Fp.add(gx, CG.b)
        //    33.   y = sqrt(gx)
        let y = Fp.sqrt(gx)
        //    34.  e3 = sgn0(u) == sgn0(y)
        const e3 = Fp.isOdd?.(u) == Fp.isOdd?.(y)
        //    35. y = CMOV(-y, y, e3)       # Select correct sign of y
        y = Fp.cmov(Fp.neg(y), y, e3)

        return { x, y }
    }
}
