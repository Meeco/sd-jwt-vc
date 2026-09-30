import {
  Hasher,
  KeyBindingVerifier,
  SDJWTPayload,
  Verifier as VerifierCallbackFn,
  VerifySDJWTOptions,
  decodeJWT,
  decodeSDJWT,
  verifySDJWT,
} from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors.js';
import { JWT, VerifyVCSDJWTOptions } from './types.js';
import { ValidTypValues } from './util.js';

const VALID_TYP_VALUES_ARRAY: string[] = Object.values(ValidTypValues);

export class Verifier {
  /**
   * Verifies a SD-JWT.
   * @param sdJWT The SD-JWT to verify.
   * @param verifierCallbackFn The verifier callback function.
   * @param hasherCallbackFn The hasher callback function.
   * @param kbVeriferCallbackFn The key binding verifier callback function.
   * @param options Validation options passed through to @meeco/sd-jwt, e.g. { time: { skip: true } }
   * to leave the credential's validity period to the caller.
   * @throws An error if the SD-JWT cannot be verified.
   * @returns The decoded SD-JWT payload.
   */
  async verifyVCSDJWT(
    sdJWT: JWT,
    verifierCallbackFn: VerifierCallbackFn,
    hasherCallbackFn: Hasher,
    kbVeriferCallbackFn?: KeyBindingVerifier,
    options?: VerifyVCSDJWTOptions,
  ): Promise<SDJWTPayload> {
    const { header: jwtHeader } = decodeJWT(sdJWT.split('~')[0]);

    if (!jwtHeader.typ || !VALID_TYP_VALUES_ARRAY.includes(jwtHeader.typ as string)) {
      throw new SDJWTVCError(
        `Invalid typ header. Expected one of ${VALID_TYP_VALUES_ARRAY.join(', ')}, received ${jwtHeader.typ}`,
      );
    }

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

    const sdJWTOptions: VerifySDJWTOptions = { time: options?.time };
    if (kbVeriferCallbackFn) {
      sdJWTOptions.kb = {
        verifier: kbVeriferCallbackFn,
        iat: options?.kb?.iat,
      };
    }
    const result = await verifySDJWT(sdJWT, verifierCallbackFn, () => Promise.resolve(hasherCallbackFn), sdJWTOptions);
    return result;
  }
}
