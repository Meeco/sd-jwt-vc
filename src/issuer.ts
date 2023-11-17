import { DisclosureFrame, SDJWTPayload, SaltGenerator, issueSDJWT } from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors.js';
import { CreateSDJWTPayload, HasherConfig, JWT, SignerConfig, VCClaims, VCClaimsWithVCDataModel } from './types.js';
import { isValidUrl } from './util.js';

export class Issuer {
  private hasher: HasherConfig;
  private signer: SignerConfig;
  private static SD_JWT_TYP = 'vc+sd-jwt';

  constructor(signer: SignerConfig, hasher: HasherConfig) {
    if (!signer?.callback || typeof signer?.callback !== 'function') {
      throw new SDJWTVCError('Signer function is required');
    }
    if (!signer?.alg || typeof signer?.alg !== 'string') {
      throw new SDJWTVCError('algo used for Signer function is required');
    }

    if (!hasher?.callback || typeof hasher?.callback !== 'function') {
      throw new SDJWTVCError('Hasher function is required');
    }
    if (!hasher?.alg || typeof hasher?.alg !== 'string') {
      throw new SDJWTVCError('algo used for Hasher function is required');
    }

    this.signer = signer;
    this.hasher = hasher;
  }

  // write getter for signer and hasher
  get getSigner() {
    return this.signer;
  }
  get getHasher() {
    return this.hasher;
  }

  /**
   * Creates a VC SD-JWT.
   * @param claims The VC claims.
   * @param sdJWTPayload The SD-JWT payload.
   * @param sdVCClaimsDisclosureFrame The SD-VC claims disclosure frame.
   * @param saltGenerator The salt generator.
   * @throws An error if the VC SD-JWT cannot be created.
   * @returns The VC SD-JWT.
   */
  async createVCSDJWT(
    vcClaims: VCClaims | VCClaimsWithVCDataModel,
    sdJWTPayload: CreateSDJWTPayload,
    sdVCClaimsDisclosureFrame: DisclosureFrame = {},
    saltGenerator?: SaltGenerator,
  ): Promise<JWT> {
    if (!vcClaims) throw new SDJWTVCError('vcClaims is required');
    if (!sdJWTPayload) throw new SDJWTVCError('sdJWTPayload is required');

    if (typeof vcClaims === 'object' && !vcClaims.vc) {
      this.validateVCClaims(vcClaims as VCClaims);
    }

    this.validateSDJWTPayload(sdJWTPayload);

    try {
      const jwt = await issueSDJWT(
        {
          typ: Issuer.SD_JWT_TYP,
          alg: this.signer.alg,
        },
        { ...sdJWTPayload, ...vcClaims },
        sdVCClaimsDisclosureFrame,
        {
          signer: this.signer.callback,
          hash: {
            alg: this.hasher.alg,
            callback: this.hasher.callback,
          },
          cnf: sdJWTPayload?.cnf,
          generateSalt: saltGenerator,
        },
      );

      return jwt;
    } catch (error: any) {
      throw new SDJWTVCError(`Failed to create VCSDJWT: ${error.message}`);
    }
  }

  /**
   * Validates the SD-JWT payload.
   * @param sdJWTPayload The SD-JWT payload to validate.
   */
  validateSDJWTPayload(sdJWTPayload: SDJWTPayload) {
    if (!sdJWTPayload.iss || !isValidUrl(sdJWTPayload.iss)) {
      throw new SDJWTVCError('Issuer iss (issuer) is required and must be a valid URL');
    }
    if (!sdJWTPayload.iat || typeof sdJWTPayload.iat !== 'number') {
      throw new SDJWTVCError('Payload iat (Issued at - seconds since Unix epoch) is required and must be a number');
    }
    if (!sdJWTPayload.cnf || typeof sdJWTPayload.cnf !== 'object' || !sdJWTPayload.cnf.jwk) {
      throw new SDJWTVCError('Payload cnf is required and must be a JWK format');
    }
    if (typeof sdJWTPayload.cnf.jwk !== 'object' || typeof sdJWTPayload.cnf.jwk.kty !== 'string') {
      throw new SDJWTVCError('Payload cnf.jwk must be valid JWK format');
    }

    if (sdJWTPayload.nbf && typeof sdJWTPayload.nbf !== 'number') {
      throw new SDJWTVCError('Payload nbf must be a number');
    }
    if (sdJWTPayload.exp && typeof sdJWTPayload.exp !== 'number') {
      throw new SDJWTVCError('Payload exp must be a number');
    }

    if (sdJWTPayload.sub && typeof sdJWTPayload.sub !== 'string') {
      throw new SDJWTVCError('Payload sub must be a string');
    }
  }

  /**
   * Validates the VC claims.
   * @param claims The VC claims to validate.
   */
  validateVCClaims(claims: VCClaims) {
    if (!claims || typeof claims !== 'object') {
      throw new SDJWTVCError('Payload claims is required and must be an object');
    }
    if (!claims.type || typeof claims.type !== 'string') {
      throw new SDJWTVCError('Payload type is required and must be a string');
    }
    if (claims.status && typeof claims.status !== 'object') {
      throw new SDJWTVCError('Payload status must be an object');
    }
  }
}
