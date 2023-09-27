import { KeyBindingVerifier, decodeJWT } from 'sd-jwt';
import { CreateSDJWTPayload, JWT, PresentSDJWTPayload, SD_JWT_FORMAT_SEPARATOR, SignerConfig } from './types';
import { generateNonce, isValidUrl } from './util';

export class Holder {
  private signer: SignerConfig;
  private static SD_KEY_BINDING_JWT_TYP = 'kb+jwt';

  constructor(signer: SignerConfig) {
    if (!signer?.callback || typeof signer?.callback !== 'function') {
      throw new Error('Signer function is required');
    }
    if (!signer?.algo || typeof signer?.algo !== 'string') {
      throw new Error('algo used for Signer function is required');
    }

    this.signer = signer;
  }

  /**
   * Gets a key binding JWT.
   * @param forVerifier The verifier to get the key binding JWT for.
   * @param nonce The nonce to use.
   * @throws An error if the key binding JWT cannot be created.
   * @returns The key binding JWT.
   */
  async getKeyBindingJWT(
    forVerifier: string,
    nonce: string = generateNonce(),
  ): Promise<{ keyBindingJWT: JWT; nonce: string }> {
    try {
      const protectedHeader = {
        typ: Holder.SD_KEY_BINDING_JWT_TYP,
        alg: this.signer.algo,
      };

      const presentSDJWTPayload: PresentSDJWTPayload = {
        aud: forVerifier,
        nonce,
        iat: Date.now(),
      };

      const jwt = await this.signer.callback(protectedHeader, presentSDJWTPayload);
      return { keyBindingJWT: jwt, nonce };
    } catch (error: any) {
      throw new Error(`Failed to get Key Binding JWT: ${error.message}`);
    }
  }

  /**
   * Presents a VC SD-JWT with a key binding JWT.
   * @param forVerifier The verifier to present the VC SD-JWT to.
   * @param sdJWT The SD-JWT to present.
   * @param keyBindingJWTVerifier The key binding JWT verifier callback function.
   * @throws An error if the VC SD-JWT cannot be presented.
   * @returns The VC SD-JWT with the key binding JWT.
   */
  async presentVerifiableCredentialSDJWT(
    forVerifier: string,
    sdJWT: JWT,
    keyBindingJWTVerifier: KeyBindingVerifier,
  ): Promise<{ vcSDJWTWithkeyBindingJWT: JWT; nonce: string }> {
    if (typeof forVerifier !== 'string' || !forVerifier || !isValidUrl(forVerifier)) {
      throw new Error('Invalid forVerifier parameter');
    }

    if (typeof sdJWT !== 'string' || !sdJWT.includes(SD_JWT_FORMAT_SEPARATOR)) {
      throw new Error('Invalid sdJWT parameter');
    }

    const [sdJWTPayload, _] = sdJWT.split(SD_JWT_FORMAT_SEPARATOR);
    const jwt = decodeJWT(sdJWTPayload);

    const { jwk: holderPublicKeyJWK } = (jwt.payload as CreateSDJWTPayload).cnf || {};

    if (!holderPublicKeyJWK) {
      throw new Error('No holder public key in SD-JWT');
    }

    const { nonce, keyBindingJWT } = await this.getKeyBindingJWT(forVerifier);

    try {
      await keyBindingJWTVerifier(keyBindingJWT, holderPublicKeyJWK);
    } catch (e) {
      throw new Error('Failed to verify key binding JWT: SD JWT holder public key does not match private key');
    }

    return { vcSDJWTWithkeyBindingJWT: `${sdJWT}${keyBindingJWT}`, nonce };
  }
}
