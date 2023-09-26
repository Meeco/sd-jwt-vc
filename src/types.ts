import { JSONWebKeySet, JWK, JWTPayload } from 'jose';

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
