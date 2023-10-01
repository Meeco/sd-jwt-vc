import { generateKeyPair } from 'jose';

import { DisclosureFrame, SDJWTPayload } from '@meeco/sd-jwt';
import { Issuer } from './issuer';
import { hasherCallbackFn, signerCallbackFn } from './test-utils/helpers';
import { HasherConfig, SignerConfig, VCClaims } from './types';
import { supportedAlgorithm } from './util';

describe('Issuer', () => {
  let issuer: Issuer;
  let hasher: HasherConfig;
  let signer: SignerConfig;

  beforeEach(async () => {
    const keyPair = await generateKeyPair(supportedAlgorithm.EdDSA);

    signer = {
      alg: supportedAlgorithm.EdDSA,
      callback: signerCallbackFn(keyPair.privateKey),
    };
    hasher = {
      alg: 'sha256',
      callback: hasherCallbackFn('sha256'),
    };

    issuer = new Issuer(signer, hasher);
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
