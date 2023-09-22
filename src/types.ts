export type Signer = (data: string | Uint8Array) => Promise<string>
export type Hasher = (data: string | Uint8Array) => Promise<string>
export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>

export const JWT_ALG = 'ES256K'
export const JWT_TYP = 'vc+sd-jwt'

export interface CredentialStatus {
  idx: string
  uri: string
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Extensible<T> = T & { [x: string]: any }

export interface Cnf {
  jwk: {
    kty: string
    crv: string
    x: string
    y: string
  }
}

export interface SdJwtCredentialPayload {
  sub?: string
  cnf: Cnf
  vc: Extensible<{
    type: string
    credentialStatus?: CredentialStatus
  }>
  nbf?: number
  aud?: string | string[]
  exp?: number
  jti?: string

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export type JWT = string
