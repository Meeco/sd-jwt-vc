import type { Hasher, JWT, SdJwtCredentialPayload, Signer } from './types.js';

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

  async createVerifiableCredentialSdJwt(payload: SdJwtCredentialPayload): Promise<JWT> {
    if (!payload.vc.type || typeof payload.vc.type !== 'string') {
      throw new Error('Payload type is required and must be a string');
    }
    if (!payload.iat || typeof payload.iat !== 'number') {
      throw new Error('Payload iat is required and must be a number');
    }
    if (!payload.cnf || typeof payload.cnf !== 'object' || !payload.cnf.jwk) {
      throw new Error('Payload cnf is required and must be a JWK format');
    }
    if (
      typeof payload.cnf.jwk !== 'object' ||
      typeof payload.cnf.jwk.kty !== 'string' ||
      typeof payload.cnf.jwk.crv !== 'string' ||
      typeof payload.cnf.jwk.x !== 'string' ||
      typeof payload.cnf.jwk.y !== 'string'
    ) {
      throw new Error('Payload cnf.jwk must be valid JWK format');
    }

    if (payload.nbf && typeof payload.nbf !== 'number') {
      throw new Error('Payload nbf must be a number');
    }
    if (payload.exp && typeof payload.exp !== 'number') {
      throw new Error('Payload exp must be a number');
    }

    if (
      payload.vc.credentialStatus &&
      (typeof payload.vc.credentialStatus !== 'object' ||
        !payload.vc.credentialStatus.idx ||
        !isValidUrl(payload.vc.credentialStatus.uri))
    ) {
      throw new Error('Payload status must be an object with idx and uri properties');
    }
    if (payload.sub && typeof payload.sub !== 'string') {
      throw new Error('Payload sub must be a string');
    }

    // Create and Sign SD-JWT

    return '';
  }
}

function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}
