/**
 * The lab's closed set of failure codes.
 *
 * These are real exported constants, not prose. The UI prints
 * `code.id` verbatim next to every verdict, and e2e/claims.spec.ts asserts
 * that the page names the actual cause rather than a generic "denied".
 *
 * `surface` says where a code is allowed to appear:
 *
 *   verdict     the headline outcome of an attempt
 *   diagnostic  a reason attached to a row or a gate, under a verdict
 *   internal    an invariant. It must never reach a user as a policy verdict;
 *               if it fires, this lab has a bug, and the tests say so.
 */
export const FAILURE_CODES = {
  POLICY_UNSATISFIED: {
    id: 'POLICY_UNSATISFIED',
    surface: 'verdict',
    title: 'Policy not satisfied',
    meaning:
      'The rows this key owns cannot be combined to reach (1, 0, ..., 0), so there is no set of reconstruction coefficients and decryption never runs.',
  },
  ATTR_MISSING: {
    id: 'ATTR_MISSING',
    surface: 'diagnostic',
    title: 'Attribute missing',
    meaning: 'A specific matrix row is labelled with an attribute this key does not carry.',
  },
  THRESHOLD_NOT_MET: {
    id: 'THRESHOLD_NOT_MET',
    surface: 'diagnostic',
    title: 'Threshold not met',
    meaning: 'A k-of-n gate had fewer than k satisfied inputs.',
  },
  COLLUSION_BLOCKED: {
    id: 'COLLUSION_BLOCKED',
    surface: 'verdict',
    title: 'Collusion blocked',
    meaning:
      'The pooled attributes satisfied the policy and decryption ran to completion, but the group element it produced was wrong, so AES-GCM rejected the tag. Nothing detected collusion; the per-key randomizers simply did not cancel.',
  },
  MALFORMED_POLICY: {
    id: 'MALFORMED_POLICY',
    surface: 'verdict',
    title: 'Malformed policy',
    meaning:
      'The policy could not be converted to a monotone span program: a gate with k outside 1..n, an empty gate, or an attribute name the scheme cannot label a row with.',
  },
  ATTRIBUTE_REUSED: {
    id: 'ATTRIBUTE_REUSED',
    surface: 'internal',
    title: 'Attribute reused (internal invariant)',
    meaning:
      'Two matrix rows carried the same label, which FAME forbids. With the indexed-copy transform in place this is unreachable, so it is an assertion rather than a verdict: if it ever fires, the transform is broken.',
  },
} as const;

export type FailureCodeId = keyof typeof FAILURE_CODES;

export const FAILURE_CODE_IDS = Object.keys(FAILURE_CODES) as FailureCodeId[];

/** Codes a user can legitimately see as the headline outcome of an attempt. */
export const VERDICT_CODES = FAILURE_CODE_IDS.filter(
  (id) => FAILURE_CODES[id].surface === 'verdict',
);

/** Codes that only ever appear as a reason under a verdict. */
export const DIAGNOSTIC_CODES = FAILURE_CODE_IDS.filter(
  (id) => FAILURE_CODES[id].surface === 'diagnostic',
);

/** Codes that must never be shown as a verdict. */
export const INTERNAL_CODES = FAILURE_CODE_IDS.filter(
  (id) => FAILURE_CODES[id].surface === 'internal',
);

/** The one success outcome, named so the UI never has to invent a string. */
export const SUCCESS_CODE = {
  id: 'RECORD_OPENED',
  title: 'Record opened',
  meaning:
    'Decryption recovered the encapsulated GT element exactly, HKDF derived the same AES key, and AES-GCM verified the tag.',
} as const;
