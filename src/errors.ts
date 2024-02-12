export enum SDJWTVCErrorCode {
  DefaultError = 'UNKNOWN_ERROR', // default in case no code is provided
  InvalidIssuer = 'INVALID_ISSUER',
  InvalidIssuedAt = 'INVALID_ISSUED_AT',
  InvalidCallback = 'INVALID_CALLBACK',
  InvalidAlgorithm = 'INVALID_ALGORITHM',
  InvalidPayload = 'INVALID_PAYLOAD',
}

export class SDJWTVCError extends Error {
  protected code: SDJWTVCErrorCode;
  protected errorType: ErrorType;
  protected extraInfo: Record<string, any>;

  constructor(errorType: ErrorType, extraInfo: Record<string, any> = {}) {
    const errorInfo = ERROR_REGISTRY[errorType];

    super(errorInfo.message);

    this.errorType = errorType;
    this.code = errorInfo.code;
    this.extraInfo = extraInfo;

    this.name = this.constructor.name;
  }

  getResponse(): string | Record<string, any> {
    return this.message;
  }

  getCode(): SDJWTVCErrorCode {
    return this.code;
  }

  getErrorType(): ErrorType {
    return this.errorType;
  }

  getExtraInfo(): Record<string, any> {
    return this.extraInfo;
  }

  equals(exception: SDJWTVCError) {
    return (
      this.getErrorType() === exception.getErrorType() &&
      JSON.stringify(this.getExtraInfo()) === JSON.stringify(exception.getExtraInfo())
    );
  }
}
export type ErrorType = keyof typeof ERROR_REGISTRY;

const ERROR_REGISTRY = {
  hasher_callback_function_is_required: {
    message: 'Hasher callback function is required',
    code: SDJWTVCErrorCode.InvalidCallback,
  },
  hasher_algorithm_is_required: {
    message: 'Hasher algorithm is required',
    code: SDJWTVCErrorCode.InvalidAlgorithm,
  },
  signer_callback_function_is_required: {
    message: 'Signer callback function is required',
    code: SDJWTVCErrorCode.InvalidCallback,
  },
  signer_algorithm_is_required: {
    message: 'Signer algorithm is required',
    code: SDJWTVCErrorCode.InvalidAlgorithm,
  },
  vcClaims_is_required: {
    message: 'vcClaims is required',
    code: SDJWTVCErrorCode.DefaultError,
  },
  sdJWTPayload_is_required: {
    message: 'sdJWTPayload is required',
    code: SDJWTVCErrorCode.DefaultError,
  },
  invalid_issuer_url: {
    message: 'Issuer iss (issuer) is required and must be a valid URL',
    code: SDJWTVCErrorCode.InvalidIssuer,
  },
  invalid_issued_at: {
    message: 'Payload iat (Issued at - seconds since Unix epoch) is required and must be a number',
    code: SDJWTVCErrorCode.InvalidIssuedAt,
  },
  invalid_cnf: {
    message: 'Payload cnf is required and must be a JWK format',
    code: SDJWTVCErrorCode.DefaultError,
  },
  invalid_cnf_jwk: {
    message: 'Payload cnf.jwk must be valid JWK format',
    code: SDJWTVCErrorCode.DefaultError,
  },
  invalid_vct_string: {
    message: 'vct value MUST be a case-sensitive string',
    code: SDJWTVCErrorCode.DefaultError,
  },
  invalid_vct_url: {
    message: 'vct value MUST be a valid URL',
    code: SDJWTVCErrorCode.InvalidIssuer,
  },
  invalid_claims_object: {
    message: 'Payload claims is required and must be an object',
    code: SDJWTVCErrorCode.DefaultError,
  },
  reserved_jwt_payload_key_in_claims: {
    message: 'Claim contains reserved JWTPayload key',
    code: SDJWTVCErrorCode.DefaultError,
  },
  reserved_jwt_payload_key_in_disclosure_frame: {
    message: 'Disclosure frame contains reserved JWTPayload key',
    code: SDJWTVCErrorCode.DefaultError,
  },
  failed_to_create_VCSDJWT: {
    message: 'Failed to create VCSDJWT',
    code: SDJWTVCErrorCode.DefaultError,
  },
  missing_key_binding_verifier_callback_function: {
    message: 'Missing key binding verifier callback function',
    code: SDJWTVCErrorCode.InvalidCallback, // Use appropriate error code
  },
  missing_aud_nonce_iat_or_sd_hash_in_key_binding_JWT: {
    message: 'Missing aud, nonce, iat or sd_hash in key binding JWT',
    code: SDJWTVCErrorCode.InvalidPayload, // Use appropriate error code
  },
  signer_function_is_required: {
    message: 'Signer function is required',
    code: SDJWTVCErrorCode.InvalidCallback,
  },
  algo_used_for_Signer_function_is_required: {
    message: 'algo used for Signer function is required',
    code: SDJWTVCErrorCode.InvalidAlgorithm,
  },
  failed_to_get_Key_Binding_JWT: {
    message: 'Failed to get Key Binding JWT',
    code: SDJWTVCErrorCode.DefaultError,
  },
  invalid_audience_parameter: {
    message: 'Invalid audience parameter',
    code: SDJWTVCErrorCode.DefaultError,
  },
  invalid_sdJWT_parameter: {
    message: 'Invalid sdJWT parameter',
    code: SDJWTVCErrorCode.DefaultError,
  },
  no_holder_public_key_in_SD_JWT: {
    message: 'No holder public key in SD-JWT',
    code: SDJWTVCErrorCode.DefaultError,
  },
  no_disclosures_in_SD_JWT: {
    message: 'No disclosures in SD-JWT',
    code: SDJWTVCErrorCode.DefaultError,
  },
  failed_to_verify_key_binding_JWT: {
    message: 'Failed to verify key binding JWT: SD JWT holder public key does not match private key',
    code: SDJWTVCErrorCode.DefaultError,
  },
  aud_mismatch: {
    message: 'aud mismatch',
    code: SDJWTVCErrorCode.DefaultError,
  },
  nonce_mismatch: {
    message: 'nonce mismatch',
    code: SDJWTVCErrorCode.DefaultError,
  },
  sd_hash_mismatch: {
    message: 'sd_hash mismatch',
    code: SDJWTVCErrorCode.DefaultError,
  },
  unsupported_algorithm: {
    message: 'unsupported algorithm',
    code: SDJWTVCErrorCode.DefaultError,
  },
  invalid_issuer_well_known_url: {
    message: 'Invalid issuer well-known URL',
    code: SDJWTVCErrorCode.DefaultError,
  },
  failed_to_fetch_or_parse_response: {
    message: 'Failed to fetch or parse the response from {issuerUrl} as JSON. Error: {error.message}',
    code: SDJWTVCErrorCode.DefaultError,
  },
  issuer_public_key_jwk_not_found: {
    message: 'Issuer public key JWK not found',
    code: SDJWTVCErrorCode.DefaultError,
  },
  issuer_response_not_found: {
    message: 'Issuer response not found',
    code: SDJWTVCErrorCode.DefaultError,
  },
  issuer_response_does_not_contain_jwks_or_jwks_uri: {
    message: 'Issuer response does not contain jwks or jwks_uri',
    code: SDJWTVCErrorCode.DefaultError,
  },
  issuer_response_from_wellknown_do_not_match_the_expected_issuer: {
    message: "The response from the issuer's well-known URI does not match the expected issuer",
    code: SDJWTVCErrorCode.InvalidIssuer,
  },
  unexpected_url: {
    message: 'Unexpected URL',
    code: SDJWTVCErrorCode.DefaultError,
  },
} as const;
