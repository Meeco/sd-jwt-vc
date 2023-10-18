import { Hasher, KeyBindingVerifier, Signer, Verifier, base64encode, decodeJWT } from '@meeco/sd-jwt';
import { createHash, randomBytes } from 'crypto';
import { JWK, JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, importJWK, jwtVerify } from 'jose';
import { NonceGenerator } from '../types';
import { defaultHashAlgorithm, supportedAlgorithm } from '../util';

export function signerCallbackFn(privateKey: Uint8Array | KeyLike): Signer {
  return async (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    return (await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey)).split('.').pop();
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

export function keyBindingVerifierCallbackFn(): KeyBindingVerifier {
  return async (kbjwt: string, holderJWK: JWK) => {
    const { header } = decodeJWT(kbjwt);

    if (!Object.values(supportedAlgorithm).includes(header.alg as supportedAlgorithm)) {
      throw new Error('unsupported algorithm');
    }

    const holderKey = await importJWK(holderJWK, header.alg);
    const verifiedKbJWT = await jwtVerify(kbjwt, holderKey);
    return !!verifiedKbJWT;
  };
}

export function verifierCallbackFn(publicKey: Uint8Array | KeyLike): Verifier {
  return async (jwt: string): Promise<boolean> => {
    const verifiedKbJWT = await jwtVerify(jwt, publicKey);
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
export function hasherCallbackFn(alg: string = defaultHashAlgorithm): Hasher {
  return (data: string): string => {
    const digest = createHash(alg).update(data).digest();
    return base64encode(digest);
  };
}

export function nonceGeneratorCallbackFn(length: number = 16): NonceGenerator {
  return () => generateNonce(length);
}

export function generateNonce(length: number = 16): string {
  return randomBytes(length).toString('base64');
}
