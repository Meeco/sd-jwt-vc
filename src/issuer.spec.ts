import * as crypto from 'crypto';
import { KeyLike, exportJWK, generateKeyPair } from 'jose';
import { SDJWTPayload } from 'sd-jwt/dist/types/types';
import { Issuer } from './issuer';
import { Hasher, VCClaims } from './types';
import { supportedAlgorithm } from './util';

describe('Issuer', () => {
  let issuer: Issuer;
  let privateKey: KeyLike | Uint8Array;
  let hasher: Hasher;
  let algorithm: supportedAlgorithm;

  beforeEach(async () => {
    algorithm = supportedAlgorithm.EdDSA;
    hasher = (data) => {
      const digest = crypto.createHash('sha256').update(data).digest();
      const hash = Buffer.from(digest).toString('base64url');
      return Promise.resolve(hash);
    };
    const keyPair = await generateKeyPair(algorithm);
    privateKey = keyPair.privateKey;
    console.log(await exportJWK(keyPair.publicKey));
    console.log(await exportJWK(keyPair.privateKey));
    issuer = new Issuer(privateKey, algorithm, hasher);
  });

  it('should create a verifiable credential SD JWT', async () => {
    const holderPublicKey = {
      kty: 'EC',
      x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
      y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
      crv: 'P-256',
    };

    const payload: SDJWTPayload = {
      iat: Date.now(),
      cnf: {
        jwk: holderPublicKey,
      },
      iss: 'https://valid.issuer.url',
    };

    const vcClaims: VCClaims = {
      type: 'VerifiableCredential',
      status: {
        idx: 'statusIndex',
        uri: 'https://valid.status.url',
      },
      person: {
        name: 'test person',
        age: 25,
      },
    };

    const jwt = await issuer.createVCSDJWT(vcClaims, payload, { person: { _sd: ['name', 'age'] } });
    console.log(jwt);

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');
  });
});
