import { JSONWebKeySet, JWK, JWTPayload } from 'jose';

export type Signer = (data: string | Uint8Array) => Promise<string>;
export type Hasher = (data: string | Uint8Array) => Promise<string>;
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>;

export const SD_JWT_TYP = 'vc+sd-jwt';
export const SD_KEY_BINDING_JWT_TYP = 'kb+jwt';
export type JWT = string;
export interface CredentialStatus {
  idx: string;
  uri: string;
}

export interface Cnf {
  jwk: JWK;
}

export interface JWTHeader {
  typ: typeof SD_JWT_TYP;
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
