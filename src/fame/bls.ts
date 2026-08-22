/**
 * BLS12-381 group plumbing for FAME.
 *
 * FAME (Agrawal & Chase, CCS 2017) is written for a **Type-3** pairing
 *   e : G1 x G2 -> GT
 * with no efficient isomorphism between the source groups. BLS12-381 as
 * exposed by @noble/curves is exactly that, which is why FAME transplants onto
 * it without any translation argument. (BSW07, by contrast, assumes a symmetric
 * e : G0 x G0 -> GT and cannot be moved here honestly; the page's Construction
 * disclosure says so, and fame.ts explains why.)
 *
 * Everything below is a thin, typed wrapper. The scheme itself lives in
 * fame.ts and is hand-rolled from the paper's Figure 3.1 so it stays
 * inspectable; only the field/curve arithmetic and RFC 9380 hash-to-curve are
 * delegated to @noble/curves.
 */
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

export type G1Point = InstanceType<typeof bls.G1.Point>;
export type G2Point = InstanceType<typeof bls.G2.Point>;
export type GTElement = ReturnType<typeof bls.pairing>;

const Fp12 = bls.fields.Fp12;

/** Order of the prime-order subgroups G1, G2, GT. Written `p` in the paper. */
export const ORDER: bigint = bls.fields.Fr.ORDER;

/** Compressed encoding sizes, in bytes. */
export const G1_BYTES = 48;
export const G2_BYTES = 96;
export const GT_BYTES = 576;

/**
 * RFC 9380 domain separation tag for this lab's hash-to-curve.
 *
 * FAME models H : {0,1}* -> G1 as a random oracle. RFC 9380 says the DST must
 * name the application, so a hash computed here can never collide with a hash
 * computed by another protocol on the same curve. The suite ID
 * `BLS12381G1_XMD:SHA-256_SSWU_RO_` is the encode-to-curve method actually used.
 */
export const HASH_DST = 'CRYPTO-LAB-ATTRIBUTE-GATE-FAME-v1_XMD:SHA-256_SSWU_RO_';

/** The two fixed public generators. g in G1 and h in G2, in the paper's notation. */
export const g1: G1Point = bls.G1.Point.BASE;
export const g2: G2Point = bls.G2.Point.BASE;

/* -------------------------------------------------------------------------- */
/* Scalars (Z_p)                                                              */
/* -------------------------------------------------------------------------- */

/** Reduce into [0, p). Handles negative inputs, which MSP matrices produce. */
export function mod(x: bigint): bigint {
  const r = x % ORDER;
  return r < 0n ? r + ORDER : r;
}

export function addMod(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function mulMod(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

/**
 * Modular inverse by the extended Euclidean algorithm.
 *
 * Hand-rolled rather than pulled from the library: FAME divides by a1 and a2
 * in every key, and by Lagrange denominators in every reconstruction, so this
 * is one of the inspectable teaching parts.
 */
export function invMod(a: bigint): bigint {
  const x = mod(a);
  if (x === 0n) throw new Error('invMod: zero has no inverse mod p');
  let [oldR, r] = [x, ORDER];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return mod(oldS);
}

export function divMod(a: bigint, b: bigint): bigint {
  return mulMod(a, invMod(b));
}

/**
 * Recover a small rational a/b from a field element, or return null.
 *
 * Lagrange coefficients are small rationals -- 2, -1, 3/2, -1/2 -- but in Z_p
 * a denominator is a modular inverse, so 3/2 prints as a 64-digit number that
 * tells a reader nothing. Rational reconstruction is the standard way back:
 * run the extended Euclidean algorithm on (p, v) and stop as soon as the
 * remainder drops below the bound; the remainder is then the numerator and the
 * accumulated cofactor is the denominator.
 *
 * The result is VERIFIED before it is returned (a * b^-1 must equal v), so a
 * value that merely happens to produce small intermediates cannot be
 * mis-rendered as a fraction it is not.
 */
export function rationalForm(
  v: bigint,
  bound = 1_000_000n,
): { readonly num: bigint; readonly den: bigint } | null {
  const value = mod(v);
  let [r0, r1] = [ORDER, value];
  let [t0, t1] = [0n, 1n];
  while (r1 > bound) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [t0, t1] = [t1, t0 - q * t1];
  }
  let num = r1;
  let den = t1;
  if (den === 0n) return null;
  if (den < 0n) {
    num = -num;
    den = -den;
  }
  if (den > bound) return null;
  if (mod(num) !== mulMod(value, den)) return null;
  return { num, den };
}

/* -------------------------------------------------------------------------- */
/* Group operations, in multiplicative notation to match the paper            */
/* -------------------------------------------------------------------------- */

/** g^x in G1. */
export function g1Pow(p: G1Point, x: bigint): G1Point {
  const e = mod(x);
  // multiply() rejects 0; the identity is the right answer for exponent 0.
  return e === 0n ? bls.G1.Point.ZERO : p.multiply(e);
}

/** h^x in G2. */
export function g2Pow(p: G2Point, x: bigint): G2Point {
  const e = mod(x);
  return e === 0n ? bls.G2.Point.ZERO : p.multiply(e);
}

/** a * b in G1 (additive on the curve, multiplicative in the paper). */
export function g1Mul(a: G1Point, b: G1Point): G1Point {
  return a.add(b);
}

export function g2Mul(a: G2Point, b: G2Point): G2Point {
  return a.add(b);
}

export function g1Inv(a: G1Point): G1Point {
  return a.negate();
}

export const G1_IDENTITY: G1Point = bls.G1.Point.ZERO;
export const G2_IDENTITY: G2Point = bls.G2.Point.ZERO;

/** Product of a list of G1 elements; the empty product is the identity. */
export function g1Product(xs: readonly G1Point[]): G1Point {
  return xs.reduce((acc, x) => acc.add(x), bls.G1.Point.ZERO);
}

/* -------------------------------------------------------------------------- */
/* Target group GT                                                            */
/* -------------------------------------------------------------------------- */

export const GT_ONE: GTElement = Fp12.ONE;

/**
 * Pairings actually computed since the last reset.
 *
 * FAME's headline efficiency result is that DECRYPTION COSTS SIX PAIRINGS
 * regardless of how large the policy is -- everything that grows with the
 * policy is exponentiation in G1, the cheap group. That is a claim worth
 * showing rather than asserting, and a wall-clock number cannot show it,
 * because a browser's timings say more about the machine than the scheme.
 * A count is exact and load-invariant, so the page prints one.
 */
let pairingCounter = 0;

export function resetPairingCount(): void {
  pairingCounter = 0;
}

export function pairingCount(): number {
  return pairingCounter;
}

export function pairing(a: G1Point, b: G2Point): GTElement {
  // The identity in either source group pairs to 1; noble rejects it as input,
  // and no pairing is computed, so none is counted.
  if (a.is0() || b.is0()) return Fp12.ONE;
  pairingCounter += 1;
  return bls.pairing(a, b);
}

export function gtMul(a: GTElement, b: GTElement): GTElement {
  return Fp12.mul(a, b);
}

export function gtDiv(a: GTElement, b: GTElement): GTElement {
  return Fp12.div(a, b);
}

export function gtInv(a: GTElement): GTElement {
  return Fp12.inv(a);
}

export function gtPow(a: GTElement, x: bigint): GTElement {
  const e = mod(x);
  if (e === 0n) return Fp12.ONE;
  return Fp12.pow(a, e);
}

export function gtEquals(a: GTElement, b: GTElement): boolean {
  return Fp12.eql(a, b);
}

export function gtProduct(xs: readonly GTElement[]): GTElement {
  return xs.reduce((acc, x) => Fp12.mul(acc, x), Fp12.ONE);
}

/* -------------------------------------------------------------------------- */
/* Serialization -- every element carries its group tag                       */
/* -------------------------------------------------------------------------- */

/**
 * A serialized group element, tagged with the group it lives in.
 *
 * The tag is not decoration. Revision 1 of this lab's brief specified BSW07
 * over BLS12-381, which is unimplementable precisely because BSW07 needs the
 * same element on both the key and the ciphertext side of a *symmetric*
 * pairing. Making the typing visible everywhere -- in the UI and in the pinned
 * vectors -- is how that mistake stays caught.
 */
export type GroupTag = 'G1' | 'G2' | 'GT' | 'Zp';

export interface TaggedElement {
  readonly group: GroupTag;
  readonly hex: string;
}

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export function g1ToHex(p: G1Point): string {
  return p.is0() ? '00'.repeat(G1_BYTES) : p.toHex(true);
}

export function g2ToHex(p: G2Point): string {
  return p.is0() ? '00'.repeat(G2_BYTES) : p.toHex(true);
}

export function gtToBytes(x: GTElement): Uint8Array {
  return Fp12.toBytes(x);
}

export function gtToHex(x: GTElement): string {
  return toHex(Fp12.toBytes(x));
}

export function scalarToHex(x: bigint): string {
  return mod(x).toString(16).padStart(64, '0');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hexToBytes: odd-length input');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`hexToBytes: bad hex at ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

/** Parse a compressed G1 point. Rejects anything not on the curve or off-subgroup. */
export function g1FromHex(hex: string): G1Point {
  if (/^0+$/.test(hex)) return bls.G1.Point.ZERO;
  return bls.G1.Point.fromHex(hex) as G1Point;
}

/** Parse a compressed G2 point. */
export function g2FromHex(hex: string): G2Point {
  if (/^0+$/.test(hex)) return bls.G2.Point.ZERO;
  return bls.G2.Point.fromHex(hex) as G2Point;
}

/** Parse a GT element from its 576-byte encoding. */
export function gtFromHex(hex: string): GTElement {
  return Fp12.fromBytes(hexToBytes(hex));
}

export function tagG1(p: G1Point): TaggedElement {
  return { group: 'G1', hex: g1ToHex(p) };
}

export function tagG2(p: G2Point): TaggedElement {
  return { group: 'G2', hex: g2ToHex(p) };
}

export function tagGT(x: GTElement): TaggedElement {
  return { group: 'GT', hex: gtToHex(x) };
}

export function tagZp(x: bigint): TaggedElement {
  return { group: 'Zp', hex: scalarToHex(x) };
}

/* -------------------------------------------------------------------------- */
/* The random oracle H : {0,1}* -> G1                                         */
/* -------------------------------------------------------------------------- */

const enc = new TextEncoder();

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/**
 * Byte encoding of the paper's hash inputs.
 *
 * Figure 3.1 writes the arguments as a bare concatenation -- `H(y l t)` for an
 * attribute and `H(0 j l t)` for a matrix column -- and the authors' reference
 * implementation concatenates decimal strings. That is ambiguous the moment an
 * attribute name ends in a digit or a column index reaches two digits
 * (`H("Doctor:1" + "0" + "0")` and `H("Doctor:10" + "0")` are the same string).
 * The one-use transform in this lab *appends indices to attribute names*, so
 * that collision is reachable here, not theoretical.
 *
 * Fix: a length-prefixed, type-tagged encoding. Same three-or-four argument
 * structure as the paper, injective by construction.
 */
export function attributeHashInput(label: string, l: 1 | 2 | 3, t: 1 | 2): Uint8Array {
  const name = enc.encode(label);
  return concatBytes(enc.encode('ATTR'), u32be(name.length), name, u32be(l), u32be(t));
}

/** Column j of the MSP, 1-indexed, matching the paper's `H(0 j l t)`. */
export function columnHashInput(j: number, l: 1 | 2 | 3, t: 1 | 2): Uint8Array {
  return concatBytes(enc.encode('COL_'), u32be(j), u32be(l), u32be(t));
}

/**
 * H : {0,1}* -> G1, instantiated with RFC 9380 hash-to-curve
 * (BLS12381G1_XMD:SHA-256_SSWU_RO_).
 *
 * FAME's proof models H as a random oracle. hash-to-curve is the standard
 * instantiation and, unlike "hash then multiply the generator", it yields a
 * point whose discrete log to g is unknown -- which is what the proof needs.
 */
export function hashToG1(input: Uint8Array): G1Point {
  return bls.G1.hashToCurve(input, { DST: HASH_DST }) as G1Point;
}

/** Memoised H over attribute labels: keys and ciphertexts hash the same inputs. */
const hashCache = new Map<string, G1Point>();

function cached(key: string, compute: () => G1Point): G1Point {
  const hit = hashCache.get(key);
  if (hit) return hit;
  const v = compute();
  hashCache.set(key, v);
  return v;
}

/** H(y, l, t) for an attribute label. */
export function hashAttribute(label: string, l: 1 | 2 | 3, t: 1 | 2): G1Point {
  return cached(`A ${label} ${l} ${t}`, () =>
    hashToG1(attributeHashInput(label, l, t)),
  );
}

/** H(0, j, l, t) for MSP column j (1-indexed). */
export function hashColumn(j: number, l: 1 | 2 | 3, t: 1 | 2): G1Point {
  return cached(`C ${j} ${l} ${t}`, () =>
    hashToG1(columnHashInput(j, l, t)),
  );
}

/** The three l-indices and two t-indices the paper loops over. */
export const L_INDICES: readonly [1, 2, 3] = [1, 2, 3];
export const T_INDICES: readonly [1, 2] = [1, 2];
