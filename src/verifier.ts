import {
  Hasher,
  KeyBindingVerifier,
  SDJWTPayload,
  Verifier as VerifierCallbackFn,
  VerifySdJwtOptions,
  decodeJWT,
  decodeSDJWT,
  verifySDJWT,
} from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors.js';
import { JWT } from './types.js';

export class Verifier {
  /**
   * Verifies a SD-JWT.
   * @param sdJWT The SD-JWT to verify.
   * @param verifierCallbackFn The verifier callback function.
   * @param hasherCallbackFn The hasher callback function.
   * @param kbVeriferCallbackFn The key binding verifier callback function.
   * @throws An error if the SD-JWT cannot be verified.
   * @returns The decoded SD-JWT payload.
   */
  async verifyVCSDJWT(
    sdJWT: JWT,
    verifierCallbackFn: VerifierCallbackFn,
    hasherCallbackFn: Hasher,
    kbVeriferCallbackFn?: KeyBindingVerifier,
  ): Promise<SDJWTPayload> {
    const { keyBindingJWT } = decodeSDJWT(sdJWT);
    if (keyBindingJWT) {
      if (!kbVeriferCallbackFn) {
        throw new SDJWTVCError('Missing key binding verifier callback function');
      }

      const decodedKeyBindingJWT = decodeJWT(keyBindingJWT);
      const { payload } = decodedKeyBindingJWT;
      const { aud, nonce, iat, sd_hash } = payload;
      if (!aud || !nonce || !iat || !sd_hash) {
        throw new SDJWTVCError('Missing aud, nonce, iat or sd_hash in key binding JWT');
      }
    }

    const options: VerifySdJwtOptions = {};
    if (kbVeriferCallbackFn) {
      options.kb = {
        verifier: kbVeriferCallbackFn,
      };
    }
    const result = await verifySDJWT(sdJWT, verifierCallbackFn, () => Promise.resolve(hasherCallbackFn), options);
    return result;
  }
}
