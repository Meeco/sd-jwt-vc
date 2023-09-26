import { randomBytes } from 'crypto';
import { JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, decodeJwt, importJWK, jwtVerify } from 'jose';
import { CreateSDJWTPayload, JWT, PresentSDJWTPayload } from './types';
import { isValidUrl, supportedAlgorithm } from './util';

export class Holder {
  private privateKey: KeyLike | Uint8Array;
  private algorithm: supportedAlgorithm;
  private static SD_JWT_FORMAT_SEPARATOR = '~';
  private static SD_KEY_BINDING_JWT_TYP = 'kb+jwt';

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

  async getKeyBindingJWT(forVerifier: string): Promise<{ keyBindingJWT: JWT; nonce: string }> {
    try {
      const protectedHeader: JWTHeaderParameters = {
        typ: Holder.SD_KEY_BINDING_JWT_TYP,
        alg: this.algorithm,
      };

      const nonce = this.generateNonce();
      const presentSDJWTPayload: PresentSDJWTPayload = {
        aud: forVerifier,
        nonce,
        iat: Date.now(),
      };

      const jwt = await new SignJWT(presentSDJWTPayload).setProtectedHeader(protectedHeader).sign(this.privateKey);
      return { keyBindingJWT: jwt, nonce };
    } catch (error: any) {
      throw new Error(`Failed to get Key Binding JWT: ${error.message}`);
    }
  }

  async presentVerifiableCredentialSDJWT(
    forVerifier: string,
    sdJWT: JWT,
  ): Promise<{ vcSDJWTWithkeyBindingJWT: JWT; nonce: string }> {
    if (typeof forVerifier !== 'string' || !forVerifier || !isValidUrl(forVerifier)) {
      throw new Error('Invalid forVerifier parameter');
    }

    if (typeof sdJWT !== 'string' || !sdJWT.includes(Holder.SD_JWT_FORMAT_SEPARATOR)) {
      throw new Error('Invalid sdJWT parameter');
    }

    const [sdJWTPayload, ...disclousres] = sdJWT.split(Holder.SD_JWT_FORMAT_SEPARATOR);
    const jwt: JWTPayload = decodeJwt(sdJWTPayload);
    const { jwk: holderPublicKey } = (jwt as CreateSDJWTPayload).cnf || {};

    if (!holderPublicKey) {
      throw new Error('No holder public key in SD-JWT');
    }

    const holderJWK = await importJWK(holderPublicKey);
    const { nonce, keyBindingJWT } = await this.getKeyBindingJWT(forVerifier);

    try {
      await jwtVerify(keyBindingJWT, holderJWK);
    } catch (e) {
      throw new Error('Failed to verify key binding JWT: SD JWT holder public key does not match private key');
    }

    return { vcSDJWTWithkeyBindingJWT: `${sdJWT}${keyBindingJWT}`, nonce };
  }

  generateNonce(length: number = 16): string {
    return randomBytes(length).toString('base64');
  }
}
