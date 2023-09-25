import { JWK, JWTPayload } from 'jose';

export type Signer = (data: string | Uint8Array) => Promise<string>;
export type Hasher = (data: string | Uint8Array) => Promise<string>;
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>;

export const JWT_ALG = 'ES256K';
export const JWT_TYP = 'vc+sd-jwt';
export type JWT = string;
export interface CredentialStatus {
  idx: string;
  uri: string;
}

export interface Cnf {
  jwk: JWK;
}

export interface JWTHeader {
  typ: typeof JWT_TYP;
  alg: string;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

export interface SdJWTPayload extends JWTPayload {
  iss: string;
  iat: number;
  cnf: Cnf;
}

export interface VCClaims {
  type: string;
  status?: CredentialStatus;
  sub?: string;
  [key: string]: unknown;
}
