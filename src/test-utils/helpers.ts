import { JWK, JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, importJWK, jwtVerify } from 'jose';
import { KeyBindingVerifier, Signer, Verifier, decodeJWT } from 'sd-jwt';
import { supportedAlgorithm } from '../util';

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

export function veriferCallbackFn(): KeyBindingVerifier {
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
