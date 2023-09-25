import { KeyLike, generateKeyPair } from 'jose';
import { Holder, supportedAlgorithm } from '../index.js';

describe('Holder', () => {
  let holder: Holder;
  let privateKey: KeyLike | Uint8Array;
  let algorithm: supportedAlgorithm;

  beforeEach(async () => {
    algorithm = supportedAlgorithm.ES256;
    const keyPair = await generateKeyPair(algorithm);
    privateKey = keyPair.privateKey;
    holder = new Holder(privateKey, algorithm);
  });

  it('should create a verifiable credential SD JWT', async () => {
    const jwt = await holder.getKeyBindingJWT('https://valid.verifier.url');
    console.log(jwt);

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');
  });
});
