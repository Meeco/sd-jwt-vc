import { JWK } from 'jose';
import {
  Hasher,
  KeyBindingVerifier,
  SDJWTPayload,
  Verifier as VerifierCallbackFn,
  decodeJWT,
  verifySDJWT,
} from 'sd-jwt';
import { JWT, SD_JWT_FORMAT_SEPARATOR } from './types';
import { isValidUrl } from './util';

export class Verifier {
  /**
   * Verifies a VC SD-JWT.
   * @param sdJWT The VC SD-JWT.
   * @param verifierCallbackFn The verifier callback function.
   * @param hasherCallbackFn The hasher callback function.
   * @param kbVeriferCallbackFn The key binding verifier callback function.
   * @returns The VC SD-JWT payload.
   */
  async verifyVerifiableCredentialSDJWT(
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
   * Fetches the issuer's public key JWK if it is not provided.
   * @param jwt The decoded JWT.
   * @param issuerPath The issuer's well-known URI suffix. For example, ' jwt-issuer/user/1234' or 'jwt-issuer'.
   * @throws An error if the issuer's public key JWK cannot be fetched.
   * @returns The issuer's public key JWK.
   */
  public async fetchIssuerPublicKeyFromIss(sdJwtVC: JWT, issuerPath: string): Promise<JWK> {
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
