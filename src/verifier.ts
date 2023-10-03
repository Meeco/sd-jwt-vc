import {
  Hasher,
  JWK,
  KeyBindingVerifier,
  SDJWTPayload,
  Verifier as VerifierCallbackFn,
  decodeJWT,
  verifySDJWT,
} from '@meeco/sd-jwt';
import { JWT, SD_JWT_FORMAT_SEPARATOR } from './types.js';
import { isValidUrl } from './util.js';

export class Verifier {
  /**
   * Verifies a SD-JWT.
   * @param sdJWT The SD-JWT to verify.
   * @param verifierCallbackFn The verifier callback function.
   * @param hasherCallbackFn The hasher callback function.
   * @param kbVeriferCallbackFn The key binding verifier callback function.
   * @throws An error if the SD-JWT cannot be verified.
   * @returns The decoded SD-JWT payload.
   */
  async verifyVCSDJWT(
    sdJWT: JWT,
    verifierCallbackFn: VerifierCallbackFn,
    hasherCallbackFn: Hasher,
    kbVeriferCallbackFn: KeyBindingVerifier,
  ): Promise<SDJWTPayload> {
    try {
      const result = await verifySDJWT(sdJWT, verifierCallbackFn, () => Promise.resolve(hasherCallbackFn), {
        kb: {
          verifier: kbVeriferCallbackFn,
        },
      });
      return result;
    } catch (error) {
      console.error(`Error verifying VC SD-JWT: ${error}`);
      throw error;
    }
  }

  /**
   * Get the issuer public key from the issuer.
   * @param sdJwtVC The SD-JWT to verify.
   * @param issuerPath The issuer path postfix to .well-known/{issuerPath}, to get the issuer public key. e.g. 'jwt-issuer/user/1234'
   * @throws An error if the issuer public key cannot be fetched.
   * @returns The issuer public key.
   */
  public async getIssuerPublicKeyFromWellKnownURI(sdJwtVC: JWT, issuerPath: string): Promise<JWK> {
    const s = sdJwtVC.split(SD_JWT_FORMAT_SEPARATOR);
    const jwt = decodeJWT(s.shift() || '');

    const wellKnownPath = `.well-known/${issuerPath}`;

    if (!jwt.payload.iss || !isValidUrl(jwt.payload.iss)) {
      throw new Error('Invalid issuer URL');
    }

    const url = new URL(jwt.payload.iss);
    const baseUrl = `${url.protocol}//${url.host}`;
    const issuerUrl = `${baseUrl}/${wellKnownPath}`;

    const response = await fetch(issuerUrl);
    const responseJson = await response.json();

    if (!responseJson) {
      throw new Error('Issuer response not found');
    }
    if (!responseJson.issuer || responseJson.issuer !== jwt.payload.iss) {
      throw new Error('Issuer response does not contain the correct issuer');
    }

    let issuerPublicKeyJWK: JWK | undefined;

    if (responseJson.jwks_uri) {
      const jwksResponse = await fetch(responseJson.jwks_uri);
      const jwksResponseJson = await jwksResponse.json();
      issuerPublicKeyJWK = this.getIssuerPublicKeyJWK(jwksResponseJson, jwt.header.kid);
    } else {
      issuerPublicKeyJWK = this.getIssuerPublicKeyJWK(responseJson.jwks, jwt.header.kid);
    }

    if (!issuerPublicKeyJWK) {
      throw new Error('Issuer public key JWK not found');
    }

    return issuerPublicKeyJWK;
  }

  /**
   * Gets the issuer public key JWK.
   * @param jwks The jwks to use.
   * @param kid The kid to use.
   * @throws An error if the issuer public key JWK cannot be found.
   * @returns The issuer public key JWK.
   */
  private getIssuerPublicKeyJWK(jwks: any, kid?: string): JWK | undefined {
    if (!jwks || !jwks.keys) {
      throw new Error('Issuer response does not contain jwks or jwks_uri');
    }

    if (kid) {
      return jwks.keys.find((key: any) => key.kid === kid);
    } else {
      return jwks.keys[0];
    }
  }
}
