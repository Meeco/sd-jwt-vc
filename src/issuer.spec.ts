import { KeyLike, generateKeyPair } from 'jose';

import { DisclosureFrame, SDJWTPayload } from 'sd-jwt';
import { Issuer } from './issuer';
import { VCClaims } from './types';
import { supportedAlgorithm } from './util';

describe('Issuer', () => {
  let issuer: Issuer;
  let privateKey: KeyLike | Uint8Array;
  let algorithm: supportedAlgorithm;

  beforeEach(async () => {
    algorithm = supportedAlgorithm.EdDSA;

    const keyPair = await generateKeyPair(algorithm);
    privateKey = keyPair.privateKey;
    issuer = new Issuer(privateKey, algorithm);
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

    const sdVCClaimsDisclosureFrame: DisclosureFrame = { person: { _sd: ['name', 'age'] } };

    const jwt = await issuer.createVCSDJWT(vcClaims, payload, sdVCClaimsDisclosureFrame);

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');
  });
});
