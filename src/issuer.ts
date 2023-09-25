import { KeyLike } from 'jose';
import { issueSDJWT } from 'sd-jwt';
import { DisclosureFrame } from 'sd-jwt/dist/types/types.js';
import { Hasher, JWT, JWT_TYP, SdJWTPayload, VCClaims, isValidUrl, sha256, supportedAlgorithm } from './index.js';

export class Issuer {
  private hasher: Hasher;
  private privateKey: KeyLike | Uint8Array;
  private algorithm: supportedAlgorithm;

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
    this.hasher = hasher || sha256;
  }

  async createVCSDJWT(claims: VCClaims, SDJWTPayload?: SdJWTPayload, SdVCClaims: DisclosureFrame = {}): Promise<JWT> {
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

    if (SDJWTPayload) {
      if (!SDJWTPayload.iss || !isValidUrl(SDJWTPayload.iss)) {
        throw new Error('Issuer iss is required and must be a valid URL');
      }
      if (!SDJWTPayload.iat || typeof SDJWTPayload.iat !== 'number') {
        throw new Error('Payload iat is required and must be a number');
      }
      if (!SDJWTPayload.cnf || typeof SDJWTPayload.cnf !== 'object' || !SDJWTPayload.cnf.jwk) {
        throw new Error('Payload cnf is required and must be a JWK format');
      }
      if (
        typeof SDJWTPayload.cnf.jwk !== 'object' ||
        typeof SDJWTPayload.cnf.jwk.kty !== 'string' ||
        typeof SDJWTPayload.cnf.jwk.crv !== 'string' ||
        typeof SDJWTPayload.cnf.jwk.x !== 'string' ||
        typeof SDJWTPayload.cnf.jwk.y !== 'string'
      ) {
        throw new Error('Payload cnf.jwk must be valid JWK format');
      }

      if (SDJWTPayload.nbf && typeof SDJWTPayload.nbf !== 'number') {
        throw new Error('Payload nbf must be a number');
      }
      if (SDJWTPayload.exp && typeof SDJWTPayload.exp !== 'number') {
        throw new Error('Payload exp must be a number');
      }

      if (SDJWTPayload.sub && typeof SDJWTPayload.sub !== 'string') {
        throw new Error('Payload sub must be a string');
      }
    }

    const getHasher = () => Promise.resolve(this.hasher);
    const getIssuerPrivateKey = () => Promise.resolve(this.privateKey);

    try {
      const jwt = await issueSDJWT({
        header: {
          typ: JWT_TYP,
          alg: this.algorithm,
        },
        payload: { ...SDJWTPayload, ...claims },
        disclosureFrame: SdVCClaims,
        alg: this.algorithm,
        getHasher,
        getIssuerPrivateKey,
        holderPublicKey: SDJWTPayload?.cnf?.jwk,
      });

      return jwt;
    } catch (error: any) {
      throw new Error(`Failed to create VCSDJWT: ${error.message}`);
    }
  }
}
