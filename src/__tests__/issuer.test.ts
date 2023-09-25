import { KeyLike, generateKeyPair } from 'jose';
import { Hasher, Issuer, SdJWTPayload, VCClaims, sha256, supportedAlgorithm } from '../index.js';

describe('Issuer', () => {
  let issuer: Issuer;
  // let mockSigner: Signer;
  let privateKey: KeyLike | Uint8Array;
  let mockHasher: Hasher;
  let algorithm: supportedAlgorithm;

  beforeEach(async () => {
    // mockSigner = jest.fn(() => Promise.resolve('mocked value'));
    algorithm = supportedAlgorithm.RS256;
    mockHasher = sha256;
    const keyPair = await generateKeyPair(algorithm);
    privateKey = keyPair.privateKey;
    issuer = new Issuer(privateKey, algorithm, mockHasher);
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
      person: {
        name: 'vijay shiyani',
        age: 25,
      },
    };

    const jwt = await issuer.createSdJWT(VCClaims, payload);
    console.log(jwt);

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');
  });
});
