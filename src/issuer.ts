import { DisclosureFrame, JWTHeaderParameters, SDJWTPayload, base64encode, issueSDJWT } from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors.js';
import { CreateSignedJWTOpts, HasherConfig, JWT, ReservedJWTClaimKeys, SignerConfig, VCClaims } from './types.js';
import { ValidTypValues, isValidUrl } from './util.js';

export class Issuer {
  private hasher: HasherConfig;
  private signer: SignerConfig;
  private static SD_JWT_TYP = ValidTypValues.DCSDJWT;

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

  get getSigner() {
    return this.signer;
  }
  get getHasher() {
    return this.hasher;
  }

  /**
   * Creates a signed SD-JWT VC.
   */
  async createSignedVCSDJWT(opts: CreateSignedJWTOpts): Promise<JWT> {
    const {
      vcClaims,
      sdJWTPayload,
      sdVCClaimsDisclosureFrame = {},
      saltGenerator,
      sdJWTHeader,
      typeMetadataGlueDocuments,
    } = opts;
    if (!vcClaims) throw new SDJWTVCError('vcClaims is required');
    if (!sdJWTPayload) throw new SDJWTVCError('sdJWTPayload is required');

    this.validateVCClaims(vcClaims as VCClaims);
    this.validateSDJWTPayload(sdJWTPayload);
    this.validateSDVCClaimsDisclosureFrame(sdVCClaimsDisclosureFrame);

    const header: JWTHeaderParameters & { vctm?: string[] } = {
      ...sdJWTHeader,
      typ: Issuer.SD_JWT_TYP,
      alg: this.signer.alg,
    };

    if (typeMetadataGlueDocuments && typeMetadataGlueDocuments.length > 0) {
      header.vctm = typeMetadataGlueDocuments.map((doc) => {
        const docString = typeof doc === 'string' ? doc : JSON.stringify(doc);
        return base64encode(docString);
      });
    }

    try {
      const jwt = await issueSDJWT(header, { ...sdJWTPayload, ...vcClaims }, sdVCClaimsDisclosureFrame, {
        signer: this.signer.callback,
        hash: {
          alg: this.hasher.alg,
          callback: this.hasher.callback,
        },
        cnf: sdJWTPayload?.cnf,
        generateSalt: saltGenerator,
      });

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

    if (
      sdJWTPayload.cnf?.jwk &&
      (typeof sdJWTPayload.cnf.jwk !== 'object' || typeof sdJWTPayload.cnf.jwk.kty !== 'string')
    ) {
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
