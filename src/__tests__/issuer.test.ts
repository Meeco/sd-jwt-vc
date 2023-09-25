import { jest } from '@jest/globals';
import { Hasher, Issuer, SdJWTPayload, Signer, VCClaims, sha256 } from '../index.js';

describe('Issuer', () => {
  let issuer: Issuer;
  let mockSigner: Signer;
  let mockHasher: Hasher;

  beforeEach(() => {
    mockSigner = jest.fn(() => Promise.resolve('mocked value'));
    mockHasher = sha256;
    issuer = new Issuer('https://valid.issuer.url', mockSigner, mockHasher);
  });

  it('should create a verifiable credential SD JWT', async () => {
    const payload: SdJWTPayload = {
      iat: Date.now(),
      cnf: {
        jwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
          y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
        },
      },
      iss: 'https://valid.issuer.url',
    };

    const VCClaims: VCClaims = {
      type: 'VerifiableCredential',
      status: {
        idx: 'statusIndex',
        uri: 'https://valid.status.url',
      },
      name: 'vijay shiyani',
    };

    const jwt = await issuer.createSdJWT(VCClaims, payload);
    console.log(jwt);

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');
  });
});
