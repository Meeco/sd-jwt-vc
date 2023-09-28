import { generateKeyPair, importJWK } from 'jose';
import { Holder } from './holder';
import { signerCallbackFn, veriferCallbackFn } from './test-utils/helpers';
import { SignerConfig } from './types';
import { nonceGeneratorCallbackFn, supportedAlgorithm } from './util';

describe('Holder', () => {
  let holder: Holder;

  beforeEach(async () => {
    const keyPair = await generateKeyPair(supportedAlgorithm.ES256);
    holder = new Holder({
      alg: supportedAlgorithm.ES256,
      callback: signerCallbackFn(keyPair.privateKey),
    });
  });

  it('should get KeyBindingJWT', async () => {
    const { keyBindingJWT } = await holder.getKeyBindingJWT('https://valid.verifier.url');

    expect(keyBindingJWT).toBeDefined();
    expect(typeof keyBindingJWT).toBe('string');
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

    const signer: SignerConfig = {
      alg: supportedAlgorithm.ES256,
      callback: signerCallbackFn(pk),
    };
    const holder = new Holder(signer);
    const issuedSDJWT =
      'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~';

    const disclosedList = [
      {
        key: 'name',
        value: 'test person',
      },
    ];
    const { vcSDJWTWithkeyBindingJWT, nonce } = await holder.presentVerifiableCredentialSDJWT(
      'https://valid.verifier.url',
      issuedSDJWT,
      veriferCallbackFn(),
      nonceGeneratorCallbackFn(),
      disclosedList,
    );

    console.log('vcSDJWTWithkeyBindingJWT: ' + vcSDJWTWithkeyBindingJWT);
    console.log('nonce: ' + nonce);
  });
});
