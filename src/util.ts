import { sha256 as sha256Hash } from '@noble/hashes/sha256';
import { concat, fromString, toString } from 'uint8arrays';

const u8a = { toString, fromString, concat };

export function sha256(payload: string | Uint8Array): Promise<string> {
  const data = typeof payload === 'string' ? fromString(payload) : payload;
  const hash = bytesToBase64url(sha256Hash(data));
  return Promise.resolve(hash);
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url');
}

export function stringToBytes(s: string): Uint8Array {
  return u8a.fromString(s);
}

export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export enum supportedAlgorithm {
  ECDH_ES_P256 = 'ECDH-ES-P256',
  ECDH_ES_P384 = 'ECDH-ES-P384',
  ECDH_ES_P521 = 'ECDH-ES-P521',
  ECDH_ES_X25519 = 'ECDH-ES-X25519',
  ECDH_ES_X448 = 'ECDH-ES-X448',
  EdDSA_Ed25519 = 'EdDSA-Ed25519',
  EdDSA_Ed448 = 'EdDSA-Ed448',
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
  RSA_OAEP_256 = 'RSA-OAEP-256',
  RSA_OAEP_384 = 'RSA-OAEP-384',
  RSA_OAEP_512 = 'RSA-OAEP-512',
  RSA_OAEP = 'RSA-OAEP',
  RSA1_5 = 'RSA1_5',
}
