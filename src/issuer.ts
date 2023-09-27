import { DisclosureFrame, SDJWTPayload, SaltGenerator, issueSDJWT } from 'sd-jwt';
import { HasherConfig, JWT, SignerConfig, VCClaims } from './types';
import { isValidUrl } from './util';

export class Issuer {
  private hasher: HasherConfig;
  private signer: SignerConfig;
  private static SD_JWT_TYP = 'vc+sd-jwt';

  constructor(signer: SignerConfig, hasher: HasherConfig) {
    if (!signer?.callback || typeof signer?.callback !== 'function') {
      throw new Error('Signer function is required');
    }
    if (!signer?.algo || typeof signer?.algo !== 'string') {
      throw new Error('algo used for Signer function is required');
    }

    if (!hasher?.callback || typeof hasher?.callback !== 'function') {
      throw new Error('Hasher function is required');
    }
    if (!hasher?.algo || typeof hasher?.algo !== 'string') {
      throw new Error('algo used for Hasher function is required');
    }

    this.signer = signer;
    this.hasher = hasher;
  }

  /**
   * Creates a VC as an SD-JWT token.
   * @param claims The VC claims.
   * @param sdJWTPayload The SD-JWT payload.
   * @param sdVCClaimsDisclosureFrame The SD-VC claims.
   * @param saltGenerator The salt generator.
   * @returns The VC as an SD-JWT token.
   */
  async createVCSDJWT(
    claims: VCClaims,
    sdJWTPayload: SDJWTPayload,
    sdVCClaimsDisclosureFrame: DisclosureFrame = {},
    saltGenerator?: SaltGenerator,
  ): Promise<JWT> {
    this.validateVCClaims(claims);

    this.validateSDJWTPayload(sdJWTPayload);

    try {
      const jwt = await issueSDJWT(
        {
          typ: Issuer.SD_JWT_TYP,
          alg: this.signer.algo,
        },
        { ...sdJWTPayload, ...claims },
        sdVCClaimsDisclosureFrame,
        {
          signer: this.signer.callback,
          hash: {
            alg: this.hasher.algo,
            callback: this.hasher.callback,
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

  /**
   * Validates the SD-JWT payload.
   * @param sdJWTPayload The SD-JWT payload to validate.
   */
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

  /**
   * Validates the VC claims.
   * @param claims The VC claims to validate.
   */
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
