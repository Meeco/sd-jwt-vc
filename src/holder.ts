import { JWK, KeyBindingVerifier, decodeJWT, decodeSDJWT } from '@meeco/sd-jwt';
import {
  CreateSDJWTPayload,
  UndisclosedList as DisclosedList,
  JWT,
  PresentSDJWTPayload,
  SD_JWT_FORMAT_SEPARATOR,
  SignerConfig,
} from './types.js';
import { isValidUrl } from './util.js';

export class Holder {
  private signer: SignerConfig;
  private static SD_KEY_BINDING_JWT_TYP = 'kb+jwt';

  /**
   * Signer Config with callback function used for signing key binding JWT.
   * @param signer
   */
  constructor(signer: SignerConfig) {
    if (!signer?.callback || typeof signer?.callback !== 'function') {
      throw new Error('Signer function is required');
    }
    if (!signer?.alg || typeof signer?.alg !== 'string') {
      throw new Error('algo used for Signer function is required');
    }

    this.signer = signer;
  }

  /**
   * Gets a key binding JWT.
   * @param audience The verifier to present the VC SD-JWT to. e.g. https://example.com/verifier
   * @param nonce The nonce to use.
   * @throws An error if the key binding JWT cannot be created.
   * @returns The key binding JWT.
   */
  async getKeyBindingJWT(audience?: string, nonce?: string): Promise<{ keyBindingJWT: JWT; nonce?: string }> {
    try {
      const protectedHeader = {
        typ: Holder.SD_KEY_BINDING_JWT_TYP,
        alg: this.signer.alg,
      };

      const presentSDJWTPayload: PresentSDJWTPayload = {
        aud: audience,
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
   * @param sdJWT The SD-JWT to present.
   * @param disclosedList The list of disclosed claims.
   * @param options The options to use.
   * @param options.nonce The nonce to use.
   * @param options.audience The verifier to present the VC SD-JWT to. e.g. https://example.com/verifier
   * @param options.keyBindingVerifierCallbackFn The callback function to verify the key binding JWT with the holder public key.
   * @throws An error if the VC SD-JWT cannot be presented.
   * @returns The VC SD-JWT with the key binding JWT.
   */
  async presentVerifiableCredentialSDJWT(
    sdJWT: JWT,
    disclosedList: DisclosedList[],
    options?: { nonce?: string; audience?: string; keyBindingVerifierCallbackFn?: KeyBindingVerifier },
  ): Promise<{ vcSDJWTWithkeyBindingJWT: JWT; nonce?: string }> {
    if (options.audience && (typeof options.audience !== 'string' || !isValidUrl(options.audience))) {
      throw new Error('Invalid audience parameter');
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

    const { keyBindingJWT } = await this.getKeyBindingJWT(options.audience, options.nonce);

    if (options.keyBindingVerifierCallbackFn && typeof options.keyBindingVerifierCallbackFn === 'function') {
      await this.verifyKeyBinding(options.keyBindingVerifierCallbackFn, keyBindingJWT, holderPublicKeyJWK);
    }

    let vcSDJWTWithkeyBindingJWT = `${sdJWT}${keyBindingJWT}`;

    vcSDJWTWithkeyBindingJWT = this.revealDisclosures(vcSDJWTWithkeyBindingJWT, disclosedList);

    return { vcSDJWTWithkeyBindingJWT: vcSDJWTWithkeyBindingJWT, nonce: options.nonce };
  }

  /**
   * Reveals the disclosed claims in the VC SD-JWT.
   * @param sdJWT The SD-JWT to reveal the claims in.
   * @param disclosedList The list of disclosed claims.
   * @throws An error if the undisclosed claims cannot be revealed.
   * @returns The VC SD-JWT with the disclosed claims.
   */
  revealDisclosures(sdJWT: JWT, disclosedList: DisclosedList[]): JWT {
    if (typeof sdJWT !== 'string' || !sdJWT.includes(SD_JWT_FORMAT_SEPARATOR)) {
      throw new Error('No disclosures in SD-JWT');
    }

    const { disclosures, keyBindingJWT } = decodeSDJWT(sdJWT);

    if (!disclosures) {
      return sdJWT;
    }

    const compactJWT = sdJWT.split(SD_JWT_FORMAT_SEPARATOR)[0];

    if (!disclosedList || disclosedList.length === 0) {
      return `${compactJWT}${SD_JWT_FORMAT_SEPARATOR}${keyBindingJWT}`;
    }

    const revealedDisclosures = disclosures.filter((disclosure) => {
      return disclosedList.some((undisclosed) => {
        return (
          (undisclosed.key && disclosure.key === undisclosed.key && disclosure.value === undisclosed.value) ||
          (!undisclosed.key && undisclosed.value && disclosure.value === undisclosed.value)
        );
      });
    });

    const revealedDisclosuresEncoded = revealedDisclosures
      .map((disclosure) => disclosure.disclosure)
      .join(SD_JWT_FORMAT_SEPARATOR);

    return `${compactJWT}${SD_JWT_FORMAT_SEPARATOR}${revealedDisclosuresEncoded}${SD_JWT_FORMAT_SEPARATOR}${keyBindingJWT}`;
  }

  /**
   * verifyKeyBinding verifies the key binding JWT with holder public key.
   * @param keyBindingVerifierCallbackFn
   * @param keyBindingJWT
   * @param holderPublicKeyJWK
   */
  async verifyKeyBinding(
    keyBindingVerifierCallbackFn: KeyBindingVerifier,
    keyBindingJWT: string,
    holderPublicKeyJWK: JWK,
  ) {
    try {
      await keyBindingVerifierCallbackFn(keyBindingJWT, holderPublicKeyJWK);
    } catch (e) {
      throw new Error('Failed to verify key binding JWT: SD JWT holder public key does not match private key');
    }
  }
}
