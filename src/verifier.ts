import { JWK, KeyLike, importJWK } from 'jose';
import { SDJWTPayload, decodeJWT, verifySDJWT } from 'sd-jwt';
import { JWT, SD_JWT_FORMAT_SEPARATOR } from './types';
import { defaultHashAlgorithm, hasherCallbackFn, isValidUrl, kbVeriferCallbackFn, verifierCallbackFn } from './util';

export class Verifier {
  /**
   * Verifies a Verifiable Credential SD-JWT.
   * @param sdJWT The Verifiable Credential SD-JWT to verify.
   * @param expectedAudienceValue The expected audience value.
   * @param expectedNonce The expected nonce.
   * @param issuerPublicKeyJWK The issuer's public key JWK.
   * @returns The SDJWTPayload if the verification is successful.
   * @throws An error if the verification fails.
   */
  async verifyVerifiableCredentialSDJWT(
    sdJWT: JWT,
    expectedAudienceValue: string,
    expectedNonce: string,
    issuerPublicKeyJWK?: JWK,
  ): Promise<SDJWTPayload> {
    this.validateInputs(sdJWT, expectedAudienceValue, expectedNonce);

    const s = sdJWT.split(SD_JWT_FORMAT_SEPARATOR);
    const jwt = decodeJWT(s.shift() || '');

    let issuerPubKey: KeyLike | Uint8Array;

    if (issuerPublicKeyJWK) {
      issuerPubKey = await importJWK(issuerPublicKeyJWK);
    } else if (jwt.payload.iss && isValidUrl(jwt.payload.iss)) {
      issuerPubKey = await this.fetchIssuerPublicKeyFromIss(jwt);
    } else {
      throw new Error('Issuer public key JWK not found');
    }

    if (!issuerPubKey) {
      throw new Error('issuerPubKey is required to verify the SD-JWT');
    }

    const result = await verifySDJWT(
      sdJWT,
      verifierCallbackFn(issuerPubKey),
      () => Promise.resolve(hasherCallbackFn(defaultHashAlgorithm)),
      {
        kb: {
          verifier: kbVeriferCallbackFn(expectedAudienceValue, expectedNonce),
        },
      },
    );

    return result;
  }

  /**
   * Validates the inputs for the verifyVerifiableCredentialSDJWT method.
   * @param sdJWT The Verifiable Credential SD-JWT to verify.
   * @param expectedAudienceValue The expected audience value.
   * @param expectedNonce The expected nonce.
   * @throws An error if any of the inputs are invalid.
   */
  private validateInputs(sdJWT: JWT, expectedAudienceValue: string, expectedNonce: string) {
    if (!sdJWT) {
      throw new Error('sdJWT is required');
    }

    if (typeof sdJWT !== 'string') {
      throw new Error('sdJWT must be a string');
    }

    if (!expectedAudienceValue) {
      throw new Error('expectedAudienceValue is required');
    }

    if (typeof expectedAudienceValue !== 'string') {
      throw new Error('expectedAudienceValue must be a string');
    }

    if (!expectedNonce) {
      throw new Error('expectedNonce is required');
    }
  }

  /**
   * Fetches the issuer's public key JWK if it is not provided.
   * @param jwt The decoded JWT.
   * @throws An error if the issuer's public key JWK cannot be fetched.
   * @returns The issuer's public key JWK.
   */
  private async fetchIssuerPublicKeyFromIss(jwt: any): Promise<KeyLike | Uint8Array> {
    if (!jwt.payload.iss || !isValidUrl(jwt.payload.iss)) {
      throw new Error('Invalid issuer URL');
    }

    const response = await fetch(jwt.payload.iss);
    const responseJson = await response.json();

    let issuerPublicKeyJWK: JWK | undefined;

    if (responseJson?.jwks_uri) {
      const jwksResponse = await fetch(responseJson.jwks_uri);
      const jwksResponseJson = await jwksResponse.json();

      issuerPublicKeyJWK = jwt.header.kid
        ? jwksResponseJson.keys.find((key: any) => key.kid === jwt.header.kid)
        : jwksResponseJson?.keys[0];
    } else {
      issuerPublicKeyJWK = responseJson?.jwks?.keys[0];
    }

    if (!issuerPublicKeyJWK) {
      throw new Error('Issuer public key JWK not found');
    }

    return importJWK(issuerPublicKeyJWK);
  }
}
