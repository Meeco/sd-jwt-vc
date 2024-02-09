import { DisclosureFrame, JWTHeaderParameters, SDJWTPayload, SaltGenerator, issueSDJWT } from '@meeco/sd-jwt';
import { SDJWTVCError, SDJWTVCErrorCode } from './errors.js';
import {
  CreateSDJWTPayload,
  CreateSignedJWTOpts,
  HasherConfig,
  JWT,
  ReservedJWTClaimKeys,
  SignerConfig,
  VCClaims,
} from './types.js';
import { isValidUrl } from './util.js';

export class Issuer {
  private static readonly SD_JWT_TYP = 'vc+sd-jwt';
  private hasher: HasherConfig;
  private signer: SignerConfig;

  constructor(signer: SignerConfig, hasher: HasherConfig) {
    this.validateConfig(signer, 'Signer');
    this.validateConfig(hasher, 'Hasher');
    this.signer = signer;
    this.hasher = hasher;
  }

  private validateConfig(config: SignerConfig | HasherConfig, configName: string) {
    if (!config.callback || typeof config.callback !== 'function') {
      throw new SDJWTVCError(`${configName} callback function is required`, SDJWTVCErrorCode.InvalidCallback);
    }
    if (!config.alg || typeof config.alg !== 'string') {
      throw new SDJWTVCError(`${configName} algorithm is required`, SDJWTVCErrorCode.InvalidAlgorithm);
    }
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
   * @deprecated This method will be removed in the next version. Use `createSignedVCSDJWT` instead.
   * @param claims The VC claims.
   * @param sdJWTPayload The SD-JWT payload.
   * @param sdVCClaimsDisclosureFrame The SD-VC claims disclosure frame.
   * @param saltGenerator The salt generator.
   * @param sdJWTHeader additional header parameters
   * @throws An error if the VC SD-JWT cannot be created.
   * @returns The VC SD-JWT.
   */
  async createVCSDJWT(
    vcClaims: VCClaims,
    sdJWTPayload: CreateSDJWTPayload,
    sdVCClaimsDisclosureFrame: DisclosureFrame = {},
    saltGenerator?: SaltGenerator,
    sdJWTHeader?: Omit<JWTHeaderParameters, 'typ' | 'alg'>,
  ): Promise<JWT> {
    return this.createSignedVCSDJWT({ vcClaims, sdJWTPayload, sdVCClaimsDisclosureFrame, saltGenerator, sdJWTHeader });
  }

  /**
   * Creates a signed SD-JWT VC.
   */
  async createSignedVCSDJWT(opts: CreateSignedJWTOpts): Promise<JWT> {
    const { vcClaims, sdJWTPayload, sdVCClaimsDisclosureFrame = {}, saltGenerator, sdJWTHeader } = opts;
    if (!vcClaims) throw new SDJWTVCError('vcClaims is required');
    if (!sdJWTPayload) throw new SDJWTVCError('sdJWTPayload is required');

    this.validateVCClaims(vcClaims as VCClaims);
    this.validateSDJWTPayload(sdJWTPayload);
    this.validateSDVCClaimsDisclosureFrame(sdVCClaimsDisclosureFrame);

    try {
      const jwt = await issueSDJWT(
        {
          ...sdJWTHeader,
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

    if (!sdJWTPayload.vct || typeof sdJWTPayload.vct !== 'string') {
      throw new SDJWTVCError('vct value MUST be a case-sensitive string');
    }

    const prefixes = ['http', 'https', 'https://', 'http://'];
    if (
      prefixes.some((prefix) => (sdJWTPayload.vct as string).startsWith(prefix)) &&
      !isValidUrl(sdJWTPayload.vct as any)
    ) {
      throw new SDJWTVCError('vct value MUST be a valid URL');
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

    for (const key of ReservedJWTClaimKeys) {
      if (key in claims) {
        throw new SDJWTVCError(`Claim contains reserved JWTPayload key: ${key}`);
      }
    }
  }

  /**
   * Validates the SD-VC claims disclosure frame.
   * @param sdVCClaimsDisclosureFrame The SD-VC claims disclosure frame to validate.
   */
  validateSDVCClaimsDisclosureFrame(sdVCClaimsDisclosureFrame: DisclosureFrame) {
    if (sdVCClaimsDisclosureFrame?._sd && Array.isArray(sdVCClaimsDisclosureFrame._sd)) {
      for (const key of sdVCClaimsDisclosureFrame._sd) {
        if (ReservedJWTClaimKeys.includes(key as any)) {
          throw new SDJWTVCError(`Disclosure frame contains reserved JWTPayload key: ${key}`);
        }
      }
    }
  }
}
