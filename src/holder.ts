import { randomBytes } from '@noble/hashes/utils';
import { JWTHeaderParameters, KeyLike, SignJWT } from 'jose';
import { JWT, PresentSDJWTPayload, SD_KEY_BINDING_JWT_TYP, bytesToBase64url, supportedAlgorithm } from './index.js';

export class Holder {
  private privateKey: KeyLike | Uint8Array;
  private algorithm: supportedAlgorithm;

  constructor(privateKey: KeyLike | Uint8Array, algorithm: supportedAlgorithm) {
    if (!privateKey) {
      throw new Error('Holder private key is required');
    }
    if (!algorithm || typeof algorithm !== 'string') {
      throw new Error(`Issuer algorithm is required and must be one of ${supportedAlgorithm}`);
    }

    this.algorithm = algorithm;
    this.privateKey = privateKey;
  }

  async getKeyBindingJWT(forVerifier: string): Promise<JWT> {
    try {
      const protectedHeader: JWTHeaderParameters = {
        typ: SD_KEY_BINDING_JWT_TYP,
        alg: this.algorithm,
      };

      const presentSDJWTPayload: PresentSDJWTPayload = {
        aud: forVerifier,
        nonce: this.generateNonce(),
        iat: Date.now(),
      };

      const jwt = await new SignJWT(presentSDJWTPayload).setProtectedHeader(protectedHeader).sign(this.privateKey);
      return jwt;
    } catch (error: any) {
      throw new Error(`Failed to get Key Binding JWT: ${error.message}`);
    }
  }

  generateNonce(): string {
    const nonceBytes = 16;
    const buffer = randomBytes(nonceBytes);
    return bytesToBase64url(buffer);
  }
}
