import { importJWK } from 'jose';
import * as sdJwt from 'sd-jwt/dist/src/issuer.js';
import { Hasher, JWT, JWT_TYP, SdJWTPayload, Signer, VCClaims, isValidUrl } from './index.js';
export class Issuer {
  private iss: string;
  private signer: Signer;
  private hasher: Hasher;

  constructor(iss: string, signer: Signer, hasher: Hasher) {
    this.iss = iss;
    this.signer = signer;
    this.hasher = hasher;
    this.validate();
  }

  validate(): void {
    if (!this.iss || !isValidUrl(this.iss)) {
      throw new Error('Issuer iss is required and must be a valid URL');
    }
    if (!this.signer || typeof this.signer !== 'function') {
      throw new Error('Issuer signer is required and must be a function');
    }
    if (!this.hasher || typeof this.hasher !== 'function') {
      throw new Error('Issuer hasher is required and must be a function');
    }
  }

  async createSdJWT(claims: VCClaims, SDJWTPayload?: SdJWTPayload): Promise<JWT> {
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

    const sdProps = Object.keys(claims).filter((key) => key !== 'type' && key !== 'credentialStatus');

    const getHasher = () => Promise.resolve(this.hasher);
    const getIssuerPrivateKey = () =>
      importJWK(
        {
          kty: 'EC',
          x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
          y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
          crv: 'P-256',
          d: 'fWfGrvu1tUqnyYHrdlpZiBsxkMoeim3EleoPEafV_yM',
        },
        'ES256',
      );
    const generateSalt = () => 'salt';

    const jwt = await sdJwt.issueSDJWT({
      header: {
        typ: JWT_TYP,
        alg: 'ES256',
      },
      payload: { ...SDJWTPayload, ...claims },
      disclosureFrame: {
        _sd: sdProps,
      },
      alg: 'ES256',
      getHasher,
      generateSalt,
      hash_alg: 'sha-256',
      getIssuerPrivateKey,
    });

    return jwt;
  }
}
