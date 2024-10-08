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
  cnf: Cnf;
  vct: string;
  status?: Record<string, any>;
}

export interface CreateSignedJWTOpts {
  vcClaims: VCClaims;
  sdJWTPayload: CreateSDJWTPayload;
  sdVCClaimsDisclosureFrame?: DisclosureFrame;
  saltGenerator?: SaltGenerator;
  sdJWTHeader?: Omit<JWTHeaderParameters, 'typ' | 'alg'>;
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
