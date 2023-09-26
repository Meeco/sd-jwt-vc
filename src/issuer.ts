import { KeyLike } from 'jose';
import { issueSDJWT } from 'sd-jwt';
import { DisclosureFrame, Hasher, SDJWTPayload } from 'sd-jwt/dist/types/types';
import { JWT, VCClaims } from './types';
import { isValidUrl, supportedAlgorithm } from './util';

export class Issuer {
  private hasher: Hasher;
  private privateKey: KeyLike | Uint8Array;
  private algorithm: supportedAlgorithm;
  private static SD_JWT_TYP = 'vc+sd-jwt';

  constructor(privateKey: KeyLike | Uint8Array, algorithm: supportedAlgorithm, hasher?: Hasher) {
    if (!privateKey) {
      throw new Error('Issuer private key is required');
    }
    if (!algorithm || typeof algorithm !== 'string') {
      throw new Error(`Issuer algorithm is required and must be one of ${supportedAlgorithm}`);
    }
    if (hasher && typeof hasher !== 'function') {
      throw new Error('Issuer hasher is required and must be a function');
    }

    this.algorithm = algorithm;
    this.privateKey = privateKey;
    this.hasher = hasher;
  }

  async createVCSDJWT(claims: VCClaims, sdJWTPayload: SDJWTPayload, SdVCClaims: DisclosureFrame = {}): Promise<JWT> {
    this.validateVCClaims(claims);

    this.validateSDJWTPayload(sdJWTPayload);

    const getHasher = () => Promise.resolve(this.hasher);
    const getIssuerPrivateKey = () => Promise.resolve(this.privateKey);

    try {
      const jwt = await issueSDJWT({
        header: {
          typ: Issuer.SD_JWT_TYP,
          alg: this.algorithm,
        },
        payload: { ...sdJWTPayload, ...claims },
        disclosureFrame: SdVCClaims,
        alg: this.algorithm,
        getHasher,
        getIssuerPrivateKey,
        holderPublicKey: sdJWTPayload?.cnf?.jwk,
      });

      return jwt;
    } catch (error: any) {
      throw new Error(`Failed to create VCSDJWT: ${error.message}`);
    }
  }

  validateSDJWTPayload(sdJWTPayload: SDJWTPayload) {
    if (!sdJWTPayload.iss || !isValidUrl(sdJWTPayload.iss)) {
      throw new Error('Issuer iss is required and must be a valid URL');
    }
    if (!sdJWTPayload.iat || typeof sdJWTPayload.iat !== 'number') {
      throw new Error('Payload iat is required and must be a number');
    }
    if (!sdJWTPayload.cnf || typeof sdJWTPayload.cnf !== 'object' || !sdJWTPayload.cnf.jwk) {
      throw new Error('Payload cnf is required and must be a JWK format');
    }
    if (
      typeof sdJWTPayload.cnf.jwk !== 'object' ||
      typeof sdJWTPayload.cnf.jwk.kty !== 'string' ||
      typeof sdJWTPayload.cnf.jwk.crv !== 'string' ||
      typeof sdJWTPayload.cnf.jwk.x !== 'string' ||
      typeof sdJWTPayload.cnf.jwk.y !== 'string'
    ) {
      throw new Error('Payload cnf.jwk must be valid JWK format');
    }

    if (sdJWTPayload.nbf && typeof sdJWTPayload.nbf !== 'number') {
      throw new Error('Payload nbf must be a number');
    }
    if (sdJWTPayload.exp && typeof sdJWTPayload.exp !== 'number') {
      throw new Error('Payload exp must be a number');
    }

    if (sdJWTPayload.sub && typeof sdJWTPayload.sub !== 'string') {
      throw new Error('Payload sub must be a string');
    }
  }

  validateVCClaims(claims: VCClaims) {
    if (!claims || typeof claims !== 'object') {
      throw new Error('Payload claims is required and must be an object');
    }
    if (!claims.type || typeof claims.type !== 'string') {
      throw new Error('Payload type is required and must be a string');
    }
    if (
      claims.credentialStatus &&
      (typeof claims.credentialStatus !== 'object' || !claims.status?.idx || !isValidUrl(claims.status?.uri))
    ) {
      throw new Error('Payload status must be an object with idx and uri properties');
    }
  }
}
