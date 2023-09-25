import { Holder } from './holder.js';
import { Issuer } from './issuer.js';
import {
  CreateSDJWTPayload,
  CredentialStatus,
  Hasher,
  IssuerMetadata,
  JWT,
  JWTHeader,
  PresentSDJWTPayload,
  SD_JWT_TYP,
  SD_KEY_BINDING_JWT_TYP,
  Signer,
  SignerAlgorithm,
  VCClaims,
} from './types.js';
import { bytesToBase64url, isValidUrl, sha256, stringToBytes, supportedAlgorithm } from './util.js';

export {
  Holder,
  Issuer,
  SD_JWT_TYP,
  SD_KEY_BINDING_JWT_TYP,
  bytesToBase64url,
  isValidUrl,
  sha256,
  stringToBytes,
  supportedAlgorithm,
};
export type {
  CredentialStatus,
  Hasher,
  IssuerMetadata,
  JWT,
  JWTHeader,
  PresentSDJWTPayload,
  CreateSDJWTPayload as SDJWTPayload,
  Signer,
  SignerAlgorithm,
  VCClaims,
};
