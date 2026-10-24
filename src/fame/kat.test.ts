/**
 * Known-answer tests against PUBLISHED vectors.
 *
 * No official FAME vectors exist -- the paper ships no test data and the
 * authors' Charm implementation pins none. What does have published vectors is
 * every standardised primitive this lab stands on, and those are the ones a
 * wiring mistake would hide behind:
 *
 *   - RFC 9380 Appendix J.9.1, BLS12381G1_XMD:SHA-256_SSWU_RO_.
 *     This is H, FAME's random oracle into G1. If the DST handling or the
 *     hash-to-curve call were wrong, every group element in the scheme would
 *     be wrong together and the round-trip tests would still pass.
 *   - RFC 9380 Appendix J.10.1, BLS12381G2_XMD:SHA-256_SSWU_RO_.
 *     RW15 independently hashes GIDs and authority-qualified attributes into
 *     G2; published Fp2 coordinates keep that new dependency honest.
 *   - RFC 5869 Appendix A, HKDF-SHA-256 test cases 1-3.
 *   - Wycheproof aes_gcm_test.json, AES-256-GCM with a 96-bit IV and 128-bit tag.
 *
 * FAME's own vectors are pinned separately, in vectors/fame-vectors.json, and
 * vectors.test.ts recomputes them by a route that never calls the scheme.
 */
import { describe, expect, it } from 'vitest';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { hashToG1, HASH_DST } from './bls';
import { aesGcmEncrypt, hkdfSha256, toHex } from './kem';
import {
  RW15_ATTRIBUTE_DST,
  RW15_GID_DST,
  rwHashAttribute,
  rwHashGid,
} from '../rw15/rw15';

const enc = new TextEncoder();

function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/* -------------------------------------------------------------------------- */
/* RFC 9380 J.9.1 -- hash-to-curve, the instantiation of FAME's oracle H       */
/* -------------------------------------------------------------------------- */

const RFC9380_DST = 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_';

const RFC9380_G1: { msg: string; x: string; y: string }[] = [
  {
    msg: '',
    x: '052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1',
    y: '08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265',
  },
  {
    msg: 'abc',
    x: '03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903',
    y: '0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d',
  },
  {
    msg: 'abcdef0123456789',
    x: '11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98',
    y: '03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709',
  },
  {
    msg: `q128_${'q'.repeat(128)}`,
    x: '15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488',
    y: '1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38',
  },
  {
    msg: `a512_${'a'.repeat(512)}`,
    x: '082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe',
    y: '05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8',
  },
];

describe('RFC 9380 J.9.1 -- BLS12381G1_XMD:SHA-256_SSWU_RO_', () => {
  for (const v of RFC9380_G1) {
    const shown = v.msg.length > 24 ? `${v.msg.slice(0, 12)}... (${v.msg.length} bytes)` : `"${v.msg}"`;
    it(`maps ${shown} to the published point`, () => {
      const p = bls.G1.hashToCurve(enc.encode(v.msg), { DST: RFC9380_DST });
      const a = p.toAffine();
      expect(a.x.toString(16).padStart(96, '0')).toBe(v.x);
      expect(a.y.toString(16).padStart(96, '0')).toBe(v.y);
    });
  }

  it("this lab's DST names this lab and follows the RFC 9380 suite form", () => {
    expect(HASH_DST.endsWith('_XMD:SHA-256_SSWU_RO_')).toBe(true);
    expect(HASH_DST).toContain('CRYPTO-LAB-ATTRIBUTE-GATE-FAME');
    expect(HASH_DST.length).toBeLessThanOrEqual(255); // RFC 9380 section 5.3.3
  });

  it('changing only the DST changes the point, so domain separation is real', () => {
    const mine = hashToG1(enc.encode('abc'));
    const rfc = bls.G1.hashToCurve(enc.encode('abc'), { DST: RFC9380_DST });
    expect(mine.toHex(true)).not.toBe(rfc.toHex(true));
  });

  it('every hashed point is in the prime-order subgroup', () => {
    for (const v of RFC9380_G1.slice(0, 3)) {
      const p = hashToG1(enc.encode(v.msg));
      expect(p.isTorsionFree()).toBe(true);
      expect(() => p.assertValidity()).not.toThrow();
    }
  });
});

/* -------------------------------------------------------------------------- */
/* RFC 9380 J.10.1 -- hash-to-curve, RW15's H and F into G2                   */
/* -------------------------------------------------------------------------- */

const RFC9380_G2_DST = 'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_';

const RFC9380_G2: {
  msg: string;
  x0: string;
  x1: string;
  y0: string;
  y1: string;
}[] = [
  {
    msg: '',
    x0: '0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a',
    x1: '05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d',
    y0: '0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92',
    y1: '12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6',
  },
  {
    msg: 'abc',
    x0: '02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6',
    x1: '139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8',
    y0: '1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48',
    y1: '00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16',
  },
  {
    msg: 'abcdef0123456789',
    x0: '121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0',
    x1: '190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c',
    y0: '05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8',
    y1: '0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be',
  },
  {
    msg: `q128_${'q'.repeat(128)}`,
    x0: '19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da',
    x1: '0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91',
    y0: '14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192',
    y1: '09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662',
  },
  {
    msg: `a512_${'a'.repeat(512)}`,
    x0: '01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534',
    x1: '11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569',
    y0: '0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e',
    y1: '03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52',
  },
];

describe('RFC 9380 J.10.1 -- BLS12381G2_XMD:SHA-256_SSWU_RO_', () => {
  for (const vector of RFC9380_G2) {
    const shown =
      vector.msg.length > 24
        ? `${vector.msg.slice(0, 12)}... (${vector.msg.length} bytes)`
        : `"${vector.msg}"`;
    it(`maps ${shown} to the published Fp2 point`, () => {
      const affine = bls.G2.hashToCurve(enc.encode(vector.msg), { DST: RFC9380_G2_DST }).toAffine();
      expect(affine.x.c0.toString(16).padStart(96, '0')).toBe(vector.x0);
      expect(affine.x.c1.toString(16).padStart(96, '0')).toBe(vector.x1);
      expect(affine.y.c0.toString(16).padStart(96, '0')).toBe(vector.y0);
      expect(affine.y.c1.toString(16).padStart(96, '0')).toBe(vector.y1);
    });
  }

  it('RW15 uses two distinct, suite-correct application DSTs', () => {
    expect(RW15_GID_DST).not.toBe(RW15_ATTRIBUTE_DST);
    for (const dst of [RW15_GID_DST, RW15_ATTRIBUTE_DST]) {
      expect(dst.endsWith('_BLS12381G2_XMD:SHA-256_SSWU_RO_')).toBe(true);
      expect(dst).toContain('CRYPTO-LAB-ATTRIBUTE-GATE-RW15');
      expect(dst.length).toBeLessThanOrEqual(255);
    }
  });

  it('RW15 GID and attribute points are valid prime-order G2 points', () => {
    for (const point of [rwHashGid('gid:alice'), rwHashAttribute('Doctor@Hospital')]) {
      expect(point.isTorsionFree()).toBe(true);
      expect(() => point.assertValidity()).not.toThrow();
    }
  });
});

/* -------------------------------------------------------------------------- */
/* RFC 5869 Appendix A -- HKDF-SHA-256                                        */
/* -------------------------------------------------------------------------- */

const RFC5869: { name: string; ikm: string; salt: string; info: string; len: number; okm: string }[] = [
  {
    name: 'A.1 basic',
    ikm: '0b'.repeat(22),
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    len: 42,
    okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  },
  {
    name: 'A.2 longer inputs and outputs',
    ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
    salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    len: 82,
    okm: 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
  },
  {
    name: 'A.3 zero-length salt and info',
    ikm: '0b'.repeat(22),
    salt: '',
    info: '',
    len: 42,
    okm: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  },
];

describe('RFC 5869 -- HKDF-SHA-256', () => {
  for (const v of RFC5869) {
    it(`reproduces ${v.name}`, async () => {
      const okm = await hkdfSha256(fromHex(v.ikm), fromHex(v.salt), fromHex(v.info), v.len);
      expect(toHex(okm)).toBe(v.okm);
    });
  }
});

/* -------------------------------------------------------------------------- */
/* Wycheproof -- AES-256-GCM, 96-bit IV, 128-bit tag                          */
/* -------------------------------------------------------------------------- */

const WYCHEPROOF_AES_GCM: {
  id: number;
  key: string;
  iv: string;
  aad: string;
  msg: string;
  ct: string;
  tag: string;
}[] = [
  {
    id: 91,
    key: '92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20',
    iv: '00112233445566778899aabb',
    aad: '00000000ffffffff',
    msg: '00010203040506070809',
    ct: 'e27abdd2d2a53d2f136b',
    tag: '9a4a2579529301bcfb71c78d4060f52c',
  },
  {
    id: 92,
    key: '29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123',
    iv: '00112233445566778899aabb',
    aad: 'aabbccddeeff',
    msg: '',
    ct: '',
    tag: '2a7d77fa526b8250cb296078926b5020',
  },
  {
    id: 93,
    key: '80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0',
    iv: '4da5bf8dfd5852c1ea12379d',
    aad: '',
    msg: '',
    ct: '',
    tag: '4771a7c404a472966cea8f73c8bfe17a',
  },
  {
    id: 94,
    key: 'cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273',
    iv: '99e23ec48985bccdeeab60f1',
    aad: '',
    msg: '2a',
    ct: '06',
    tag: '633c1e9703ef744ffffb40edf9d14355',
  },
  {
    id: 95,
    key: '51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152',
    iv: '4f07afedfdc3b6c2361823d3',
    aad: '',
    msg: 'be3308f72a2c6aed',
    ct: 'cf332a12fdee800b',
    tag: '602e8d7c4799d62c140c9bb834876b09',
  },
  {
    id: 96,
    key: '67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb',
    iv: '68ab7fdbf61901dad461d23c',
    aad: '',
    msg: '51f8c1f731ea14acdb210a6d973e07',
    ct: '43fc101bff4b32bfadd3daf57a590e',
    tag: 'ec04aacb7148a8b8be44cb7eaf4efa69',
  },
];

describe('Wycheproof -- AES-256-GCM (96-bit IV, 128-bit tag)', () => {
  for (const v of WYCHEPROOF_AES_GCM) {
    it(`reproduces tcId ${v.id}`, async () => {
      const out = await aesGcmEncrypt(
        fromHex(v.key),
        fromHex(v.iv),
        fromHex(v.aad),
        fromHex(v.msg),
      );
      // WebCrypto returns ciphertext with the tag appended.
      expect(toHex(out)).toBe(v.ct + v.tag);
    });
  }
});
