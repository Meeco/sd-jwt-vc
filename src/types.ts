import { Hasher, JWK, JWTPayload, Signer } from '@meeco/sd-jwt';
import { supportedAlgorithm } from './util.js';

export const SD_JWT_FORMAT_SEPARATOR = '~';

export type JWT = string;
export interface CredentialStatus {
  idx: string;
  uri: string;
}

export interface Cnf {
  jwk: JWK;
}

export interface JWTHeader {
  typ: string;
  alg: string;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

export interface CreateSDJWTPayload extends JWTPayload {
  iss: string;
  iat: number;
  cnf: Cnf;
}

export interface PresentSDJWTPayload extends JWTPayload {
  nonce: string;
  aud: string;
  iat: number;
}

export interface VCClaims {
  type: string;
  status?: CredentialStatus;
  sub?: string;
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

export type UndisclosedList = { key?: string; value: string };
