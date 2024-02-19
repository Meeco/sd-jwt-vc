import {
  Disclosure,
  GetHasher,
  Hasher,
  JWK,
  JWTHeaderParameters,
  KeyBindingVerifier,
  base64encode,
  decodeJWT,
  decodeSDJWT,
} from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors.js';
import {
  CreateSDJWTPayload,
  JWT,
  PresentSDJWTPayload,
  SD_JWT_FORMAT_SEPARATOR,
  SD_KEY_BINDING_JWT_TYP,
  SignerConfig,
} from './types.js';
import { defaultHashAlgorithm, isValidUrl } from './util.js';

export class Holder {
  private signer: SignerConfig;
  private hasherFnResolver: GetHasher;

  public static SD_KEY_BINDING_JWT_TYP = SD_KEY_BINDING_JWT_TYP;

  /**
   * Signer Config with callback function used for signing key binding JWT.
   * @param signer
   * Hasher function resolver
   * @param hasherFnResolver
   */
  constructor(signer: SignerConfig, hasherFnResolver: GetHasher) {
    if (!signer?.callback || typeof signer?.callback !== 'function') {
      throw new SDJWTVCError('Signer function is required');
    }
    if (!signer?.alg || typeof signer?.alg !== 'string') {
      throw new SDJWTVCError('algo used for Signer function is required');
    }

    if (typeof hasherFnResolver !== 'function') {
      throw new SDJWTVCError('Hasher function resolver is required');
    }

    this.signer = signer;
    this.hasherFnResolver = hasherFnResolver;
  }

  get getSigner() {
    return this.signer;
  }

  async getHasher(alg: string) {
    return this.hasherFnResolver(alg);
  }

  /**
   * Gets a key binding JWT.
   * @param audience The verifier to present the VC SD-JWT to. e.g. https://example.com/verifier
   * @param nonce The nonce to use.
   * @throws An error if the key binding JWT cannot be created.
   * @returns The key binding JWT.
   */
  async getKeyBindingJWT(
    audience: string,
    nonce: string,
    sdHash: string,
    header?: Omit<JWTHeaderParameters, 'typ' | 'alg'>,
  ): Promise<{ keyBindingJWT: JWT; nonce?: string }> {
    try {
      const protectedHeader = {
        ...header,
        typ: SD_KEY_BINDING_JWT_TYP,
        alg: this.signer.alg,
      };

      const presentSDJWTPayload: PresentSDJWTPayload = {
        aud: audience,
        nonce,
        sd_hash: sdHash,
        iat: Math.floor(Date.now() / 1000),
      };

      const signature: string = await this.signer.callback(protectedHeader, presentSDJWTPayload);

      const jwt: string = [
        base64encode(JSON.stringify(protectedHeader)),
        base64encode(JSON.stringify(presentSDJWTPayload)),
        signature,
      ].join('.');

      return { keyBindingJWT: jwt, nonce };
    } catch (error: any) {
      throw new SDJWTVCError(`Failed to get Key Binding JWT: ${error.message}`);
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
  async presentVCSDJWT(
    sdJWT: JWT,
    disclosedList: Disclosure[],
    options?: {
      nonce?: string;
      audience?: string;
      keyBindingVerifyCallbackFn?: KeyBindingVerifier;
      kbJWTHeader?: Omit<JWTHeaderParameters, 'typ' | 'alg'>;
    },
  ): Promise<{ vcSDJWTWithkeyBindingJWT: JWT; nonce?: string }> {
    if (options.audience && (typeof options.audience !== 'string' || !isValidUrl(options.audience))) {
      throw new SDJWTVCError('Invalid audience parameter');
    }

    if (typeof sdJWT !== 'string' || !sdJWT.includes(SD_JWT_FORMAT_SEPARATOR)) {
      throw new SDJWTVCError('Invalid sdJWT parameter');
    }

    const [sdJWTPayload, _] = sdJWT.split(SD_JWT_FORMAT_SEPARATOR);
    const jwt = decodeJWT(sdJWTPayload);

    const { jwk: holderPublicKeyJWK } = (jwt.payload as CreateSDJWTPayload).cnf || {};

    if (!holderPublicKeyJWK) {
      throw new SDJWTVCError('No holder public key in SD-JWT');
    }

    const shHashingAlgorithm = (jwt.payload['_sd_alg'] as string) || defaultHashAlgorithm;
    const hasher: Hasher = await this.getHasher(shHashingAlgorithm);

    const vcSDJWTWithSelectedDisclosures = this.selectDisclosures(sdJWT, disclosedList);
    const sdJwtHash: string = hasher(vcSDJWTWithSelectedDisclosures);

    const { keyBindingJWT } = await this.getKeyBindingJWT(
      options.audience,
      options.nonce,
      sdJwtHash,
      options.kbJWTHeader,
    );

    if (options.keyBindingVerifyCallbackFn && typeof options.keyBindingVerifyCallbackFn === 'function') {
      await this.verifyKeyBinding(options.keyBindingVerifyCallbackFn, keyBindingJWT, holderPublicKeyJWK);
    }

    const vcSDJWTWithkeyBindingJWT = `${vcSDJWTWithSelectedDisclosures}${keyBindingJWT}`;

    return { vcSDJWTWithkeyBindingJWT: vcSDJWTWithkeyBindingJWT, nonce: options.nonce };
  }

  /**
   * Select the disclosed claims in the VC SD-JWT.
   * @param sdJWT The compact SD-JWT.
   * @param disclosuresList The list of disclosures to be added to the SD-JWT presentation.
   * @throws An error if the disclosed claims cannot be selected.
   * @returns The VC SD-JWT with the disclosed claims.
   */
  selectDisclosures(sdJWT: JWT, disclosuresList: Disclosure[]): JWT {
    if (typeof sdJWT !== 'string' || !sdJWT.includes(SD_JWT_FORMAT_SEPARATOR)) {
      throw new SDJWTVCError('No disclosures in SD-JWT');
    }

    const { disclosures } = decodeSDJWT(sdJWT);

    if (!disclosures) {
      return sdJWT;
    }

    const compactJWT = sdJWT.split(SD_JWT_FORMAT_SEPARATOR)[0];

    if (!disclosuresList || disclosuresList.length === 0) {
      return `${compactJWT}${SD_JWT_FORMAT_SEPARATOR}`;
    }

    const selectedDisclosures = disclosures.filter((disclosure) => {
      return disclosuresList.some((disclosed) => disclosed.disclosure === disclosure.disclosure);
    });

    if (selectedDisclosures.length === 0) {
      return `${compactJWT}${SD_JWT_FORMAT_SEPARATOR}`;
    }

    const selectedDisclosuresEncoded = selectedDisclosures
      .map((disclosure) => disclosure.disclosure)
      .join(SD_JWT_FORMAT_SEPARATOR);

    return `${compactJWT}${SD_JWT_FORMAT_SEPARATOR}${selectedDisclosuresEncoded}${SD_JWT_FORMAT_SEPARATOR}`;
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
      throw new SDJWTVCError('Failed to verify key binding JWT: SD JWT holder public key does not match private key');
    }
  }
}
