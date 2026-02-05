import { DisclosureFrame, Hasher, JWK, JWTHeaderParameters, JWTPayload, SaltGenerator, Signer } from '@meeco/sd-jwt';
import { supportedAlgorithm } from './util.js';

export const SD_JWT_FORMAT_SEPARATOR = '~';

export const SD_KEY_BINDING_JWT_TYP = 'kb+jwt';

export type JWT = string;

export interface Cnf {
  jwk: JWK;
}

export interface JWTHeader {
  typ: string;
  alg: string;
  [x: string]: any;
}

export interface CreateSDJWTPayload extends JWTPayload {
  iss: string;
  iat: number;
  cnf?: Cnf;
  vct: string;
  status?: Record<string, any>;
}

export interface CreateSignedJWTOpts {
  vcClaims: VCClaims;
  sdJWTPayload: CreateSDJWTPayload;
  sdVCClaimsDisclosureFrame?: DisclosureFrame;
  saltGenerator?: SaltGenerator;
  sdJWTHeader?: Omit<JWTHeaderParameters, 'typ' | 'alg'>;
  typeMetadataGlueDocuments?: Array<Record<string, any> | string>;
}

export interface PresentSDJWTPayload extends JWTPayload {
  nonce: string;
  aud: string;
  iat: number;
}

export interface VCClaims {
  [key: string]: unknown;
}

export interface IssuerMetadata {
  issuer: string;
  jwks?: JSONWebKeySet;
  jwks_uri?: string;
}

export type HasherConfig = {
  alg: string;
  callback: Hasher;
};

export type SignerConfig = {
  alg: supportedAlgorithm;
  callback: Signer;
};

export interface JSONWebKeySet {
  keys: JWK[];
}

export type NonceGenerator = (length?: number) => string;

export type CreateSDJWTPayloadKeys = keyof CreateSDJWTPayload;
export const ReservedJWTClaimKeys: CreateSDJWTPayloadKeys[] = [
  'iss',
  'iat',
  'cnf',
  'vct',
  'status',
  'jti',
  'sub',
  'aud',
  'nbf',
  'exp',
];

/**
 * Represents the structure of a Type Metadata document as defined in the SD-JWT VC specification (Section 6.2).
 */
export interface TypeMetadata {
  vct?: string;
  name?: string;
  description?: string;
  extends?: string; // URI
  display?: Array<Record<string, any>>;
  claims?: Array<Record<string, any>>;
  /**
   * OPTIONAL. An embedded JSON Schema document describing the structure of the Verifiable Credential.
   * MUST NOT be used if schema_uri is present.
   */
  schema?: Record<string, any>;
  /**
   * OPTIONAL. A URL pointing to a JSON Schema document.
   * MUST NOT be used if schema is present.
   */
  schema_uri?: string;

  /**
   * OPTIONAL. integrity metadata for vct, extends, schema_uri, and similar URIs.
   * Value MUST be an "integrity metadata" string per W3C.SRI.
   */
  'schema_uri#integrity'?: string;
  'vct#integrity'?: string;
  'extends#integrity'?: string;

  [key: string]: any;
}
