export enum SDJWTVCErrorCode {
  DefaultError = 'UNKNOWN_ERROR', // default in case no code is provided
  InvalidIssuer = 'INVALID_ISSUER',
  InvalidIssuedAt = 'INVALID_ISSUED_AT',
  InvalidCallback = 'INVALID_CALLBACK',
  InvalidAlgorithm = 'INVALID_ALGORITHM',
}

export class SDJWTVCError extends Error {
  code: SDJWTVCErrorCode;

  constructor(message: any, code: SDJWTVCErrorCode = SDJWTVCErrorCode.DefaultError) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}
