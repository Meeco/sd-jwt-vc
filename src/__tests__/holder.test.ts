import { KeyLike, generateKeyPair, importJWK } from 'jose';
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

  it('should get KeyBindingJWT', async () => {
    const jwt = await holder.getKeyBindingJWT('https://valid.verifier.url');
    // console.log(jwt);

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');
  });

  it('should present VerifiableCredential SD JWT With KeyBindingJWT', async () => {
    const _publicJwk = {
      kty: 'EC',
      x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
      y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
      crv: 'P-256',
    };
    const privateKey = {
      kty: 'EC',
      x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
      y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
      crv: 'P-256',
      d: '9Ie2xvzUdQBGCjT9ktsZYGzwG4hOWea-zvCQSQSWJxk',
    };

    const pk = await importJWK(privateKey);
    const holder = new Holder(pk, supportedAlgorithm.ES256);
    const issuedSDJWT =
      'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2Mjg1MTk3MTQsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbIlhjOUx0VFV3c3hWSnFScllhS1Jiell1VWdzM1dxbloxXzVlU1NSSzJFZDQiLCJRbVNGd1hzajlOdXoxbEdGcDRVcjZtc09yOEVKWFpFSFpYTFFqWWU5dktFIl19fQ.1ih_e4iEAQFQvNHGwbxiYMcGoT0TixQhgoNJ3p8ZVj8zGGcn81g1hMVTVlZ4uag_1PvGxzTMeZKXjvzsE8HWAg~WyJYRW1icWhvbGRONWVMaWkxIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJGcDhxVVg3QjY0eUtrNVNCIiwiYWdlIiwyNV0~';

    const sdJWTWithKeyBinding = await holder.presentVerifiableCredentialSDJWT(
      'https://valid.verifier.url',
      issuedSDJWT,
    );

    console.log(sdJWTWithKeyBinding);
  });
});
