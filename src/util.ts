import { createHash, randomBytes } from 'crypto';
import { JWK, JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, importJWK, jwtVerify } from 'jose';
import { Hasher, KeyBindingVerifier, Signer, Verifier, base64encode, decodeJWT } from 'sd-jwt';

export enum supportedAlgorithm {
  EdDSA = 'EdDSA',
  ES256 = 'ES256',
  ES256K = 'ES256K',
  ES384 = 'ES384',
  ES512 = 'ES512',
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',
}

export const defaultHashAlgorithm = 'sha256';

export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export function signerCallbackFn(privateKey: Uint8Array | KeyLike): Signer {
  return (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    return new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey);
  };
}

export function kbVeriferCallbackFn(expectedAud: string, expectedNonce: string): KeyBindingVerifier {
  return async (kbjwt: string, holderJWK: JWK) => {
    const { header, payload } = decodeJWT(kbjwt);

    if (expectedAud || expectedNonce) {
      if (payload.aud !== expectedAud) {
        throw new Error('aud mismatch');
      }
      if (payload.nonce !== expectedNonce) {
        throw new Error('nonce mismatch');
      }
    }

    if (!Object.values(supportedAlgorithm).includes(header.alg as supportedAlgorithm)) {
      throw new Error('unsupported algorithm');
    }

    const holderKey = await importJWK(holderJWK, header.alg);
    const verifiedKbJWT = await jwtVerify(kbjwt, holderKey);
    return !!verifiedKbJWT;
  };
}

export function verifierCallbackFn(issuerPublicKey: Uint8Array | KeyLike): Verifier {
  return async (vcSDJWT: string): Promise<boolean> => {
    const verifiedKbJWT = await jwtVerify(vcSDJWT, issuerPublicKey);
    return !!verifiedKbJWT;
  };
}
/**
 *
 * The `algorithm` is dependent on the available algorithms supported by the
 * version of OpenSSL on the platform. Examples are `'sha256'`, `'sha512'`, etc.
 * On recent releases of OpenSSL, `openssl list -digest-algorithms` will
 * display the available digest algorithms.
 * @param algo
 * @returns
 */
export function hasherCallbackFn(algo: string = defaultHashAlgorithm): Hasher {
  return (data: string): string => {
    const digest = createHash(algo).update(data).digest();
    return base64encode(digest);
  };
}

export function generateNonce(length: number = 16): string {
  return randomBytes(length).toString('base64');
}
