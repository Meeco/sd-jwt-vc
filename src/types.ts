import { Hasher, Signer } from 'sd-jwt';
import { supportedAlgorithm } from './util';

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
  algo: string;
  callback: Hasher;
};

export type SignerConfig = {
  algo: supportedAlgorithm;
  callback: Signer;
};

/**
 * JOSE Types
 */

/** Recognized JWT Claims Set members, any other members may also be present. */
export interface JWTPayload {
  /**
   * JWT Issuer
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}
   */
  iss?: string;

  /**
   * JWT Subject
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2 RFC7519#section-4.1.2}
   */
  sub?: string;

  /**
   * JWT Audience
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 RFC7519#section-4.1.3}
   */
  aud?: string | string[];

  /**
   * JWT ID
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7 RFC7519#section-4.1.7}
   */
  jti?: string;

  /**
   * JWT Not Before
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5 RFC7519#section-4.1.5}
   */
  nbf?: number;

  /**
   * JWT Expiration Time
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4 RFC7519#section-4.1.4}
   */
  exp?: number;

  /**
   * JWT Issued At
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6 RFC7519#section-4.1.6}
   */
  iat?: number;

  /** Any other JWT Claim Set member. */
  [propName: string]: unknown;
}

/**
 * JSON Web Key ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK}). "RSA", "EC", "OKP", and "oct"
 * key types are supported.
 */
export interface JWK {
  /** JWK "alg" (Algorithm) Parameter. */
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  /** JWK "ext" (Extractable) Parameter. */
  ext?: boolean;
  k?: string;
  /** JWK "key_ops" (Key Operations) Parameter. */
  key_ops?: string[];
  /** JWK "kid" (Key ID) Parameter. */
  kid?: string;
  /** JWK "kty" (Key Type) Parameter. */
  kty?: string;
  n?: string;
  oth?: Array<{
    d?: string;
    r?: string;
    t?: string;
  }>;
  p?: string;
  q?: string;
  qi?: string;
  /** JWK "use" (Public Key Use) Parameter. */
  use?: string;
  x?: string;
  y?: string;
  /** JWK "x5c" (X.509 Certificate Chain) Parameter. */
  x5c?: string[];
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter. */
  x5t?: string;
  /** "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter. */
  'x5t#S256'?: string;
  /** JWK "x5u" (X.509 URL) Parameter. */
  x5u?: string;

  [propName: string]: unknown;
}

/** JSON Web Key Set */
export interface JSONWebKeySet {
  keys: JWK[];
}
