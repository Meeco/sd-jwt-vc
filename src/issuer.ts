import { DisclosureFrame, JWTHeaderParameters, SDJWTPayload, SaltGenerator, issueSDJWT } from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors.js';
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
    this.validateSignerConfig(signer);
    this.validateHahserConfig(hasher);
    this.signer = signer;
    this.hasher = hasher;
  }
  private validateSignerConfig(config: SignerConfig | HasherConfig) {
    if (!config.callback || typeof config.callback !== 'function') {
      throw new SDJWTVCError('signer_callback_function_is_required');
    }
    if (!config.alg || typeof config.alg !== 'string') {
      throw new SDJWTVCError('signer_algorithm_is_required');
    }
  }

  private validateHahserConfig(config: SignerConfig | HasherConfig) {
    if (!config.callback || typeof config.callback !== 'function') {
      throw new SDJWTVCError('hasher_callback_function_is_required');
    }
    if (!config.alg || typeof config.alg !== 'string') {
      throw new SDJWTVCError('hasher_algorithm_is_required');
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
    if (!vcClaims) throw new SDJWTVCError('vcClaims_is_required');
    if (!sdJWTPayload) throw new SDJWTVCError('sdJWTPayload_is_required');

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
      throw new SDJWTVCError('failed_to_create_VCSDJWT', { reason: error.message });
    }
  }

  /**
   * Validates the SD-JWT payload.
   * @param sdJWTPayload The SD-JWT payload to validate.
   */
  validateSDJWTPayload(sdJWTPayload: SDJWTPayload) {
    if (!sdJWTPayload.iss || !isValidUrl(sdJWTPayload.iss)) {
      throw new SDJWTVCError('invalid_issuer_url');
    }
    if (!sdJWTPayload.iat || typeof sdJWTPayload.iat !== 'number') {
      throw new SDJWTVCError('invalid_issued_at');
    }
    if (!sdJWTPayload.cnf || typeof sdJWTPayload.cnf !== 'object' || !sdJWTPayload.cnf.jwk) {
      throw new SDJWTVCError('invalid_cnf');
    }
    if (typeof sdJWTPayload.cnf.jwk !== 'object' || typeof sdJWTPayload.cnf.jwk.kty !== 'string') {
      throw new SDJWTVCError('invalid_cnf_jwk');
    }

    if (!sdJWTPayload.vct || typeof sdJWTPayload.vct !== 'string') {
      throw new SDJWTVCError('invalid_vct_string');
    }

    const prefixes = ['http', 'https', 'https://', 'http://'];
    if (
      prefixes.some((prefix) => (sdJWTPayload.vct as string).startsWith(prefix)) &&
      !isValidUrl(sdJWTPayload.vct as any)
    ) {
      throw new SDJWTVCError('invalid_vct_url');
    }
  }

  /**
   * Validates the VC claims.
   * @param claims The VC claims to validate.
   */
  validateVCClaims(claims: VCClaims) {
    if (!claims || typeof claims !== 'object') {
      throw new SDJWTVCError('invalid_claims_object');
    }

    for (const key of ReservedJWTClaimKeys) {
      if (key in claims) {
        throw new SDJWTVCError('reserved_jwt_payload_key_in_claims', { reason: key });
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
          throw new SDJWTVCError('reserved_jwt_payload_key_in_disclosure_frame', { reason: key });
        }
      }
    }
  }
}
