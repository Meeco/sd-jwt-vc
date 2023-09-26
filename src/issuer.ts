import { KeyLike } from 'jose';
import { DisclosureFrame, Hasher, SDJWTPayload, SaltGenerator, Signer, issueSDJWT } from 'sd-jwt';
import { JWT, VCClaims } from './types';
import { defaultHashAlgorithm, hasherCallbackFn, isValidUrl, signerCallbackFn, supportedAlgorithm } from './util';

export class Issuer {
  private hasher: Hasher;
  private signer: Signer;
  private algorithm: supportedAlgorithm;
  private static SD_JWT_TYP = 'vc+sd-jwt';

  constructor(
    privateKey: KeyLike | Uint8Array,
    algorithm: supportedAlgorithm,
    hasherAlgo: string = defaultHashAlgorithm,
  ) {
    if (!privateKey) {
      throw new Error('Issuer private key is required');
    }
    if (!algorithm || typeof algorithm !== 'string') {
      throw new Error(`Issuer algorithm is required and must be one of ${supportedAlgorithm}`);
    }
    if (hasherAlgo && typeof hasherAlgo !== 'string') {
      throw new Error('hasherAlgo must be available algorithms supported by OpenSSL');
    }

    this.algorithm = algorithm;
    this.hasher = hasherCallbackFn(hasherAlgo);
    this.signer = signerCallbackFn(privateKey);
  }

  async createVCSDJWT(
    claims: VCClaims,
    sdJWTPayload: SDJWTPayload,
    SdVCClaims: DisclosureFrame = {},
    saltGenerator?: SaltGenerator,
  ): Promise<JWT> {
    this.validateVCClaims(claims);

    this.validateSDJWTPayload(sdJWTPayload);

    try {
      const jwt = await issueSDJWT(
        {
          typ: Issuer.SD_JWT_TYP,
          alg: this.algorithm,
        },
        { ...sdJWTPayload, ...claims },
        SdVCClaims,
        {
          signer: this.signer,
          hash: {
            alg: defaultHashAlgorithm,
            callback: this.hasher,
          },
          cnf: sdJWTPayload?.cnf,
          generateSalt: saltGenerator,
        },
      );

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
