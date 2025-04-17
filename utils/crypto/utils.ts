// returns a new array with the xor of a ^ b
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length != b.length) {
        throw new Error("Error: incompatible sizes")
    }

    const ret = new Uint8Array(a.length)

    for (let i = 0; i < a.length; i++) {
        ret[i] = a[i] ^ b[i]
    }

    return ret
}