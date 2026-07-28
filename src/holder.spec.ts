import { decodeJWT, decodeSDJWT } from '@meeco/sd-jwt';
import { generateKeyPair, importJWK } from 'jose';
import { Holder } from './holder';
import { hasherCallbackFn, keyBindingVerifierCallbackFn, signerCallbackFn } from './test-utils/helpers';
import { SD_KEY_BINDING_JWT_TYP, SignerConfig } from './types';
import { supportedAlgorithm } from './util';

describe('Holder', () => {
  let holder: Holder;

  const testHasherFn = (alg: string) => Promise.resolve(hasherCallbackFn(alg));

  beforeEach(async () => {
    const keyPair = await generateKeyPair(supportedAlgorithm.ES256);
    holder = new Holder(
      {
        alg: supportedAlgorithm.ES256,
        callback: signerCallbackFn(keyPair.privateKey),
      },
      testHasherFn,
    );
  });

  describe('constructor', () => {
    it('should throw an error if signer callback is not provided', () => {
      expect(() => new Holder({ alg: supportedAlgorithm.ES256, callback: undefined }, testHasherFn)).toThrow(
        'Signer function is required',
      );
    });

    it('should throw an error if signer alg is not provided', () => {
      expect(() => new Holder({ alg: undefined, callback: () => Promise.resolve('') }, testHasherFn)).toThrow(
        'algo used for Signer function is required',
      );
    });

    it('should throw an error if getHasherFn is not provided', () => {
      expect(
        () => new Holder({ alg: supportedAlgorithm.ES256, callback: () => Promise.resolve('') }, undefined),
      ).toThrow('Hasher function resolver is required');
    });

    it('should create an instance of Holder if all required parameters are provided', () => {
      const signer = { callback: () => Promise.resolve(''), alg: supportedAlgorithm.ES256 };
      const holder = new Holder(signer, testHasherFn);
      expect(holder).toBeInstanceOf(Holder);
      expect(holder.getSigner).toEqual(signer);
    });
  });

  it('should get KeyBindingJWT', async () => {
    const nonce = 'nIdBbNgRqCXBl8YOkfVdg==';
    const verifierURL = 'https://valid.verifier.url';
    const sdHash = 'disclosureDigest';

    const { keyBindingJWT } = await holder.getKeyBindingJWT(verifierURL, nonce, sdHash);

    expect(keyBindingJWT).toBeDefined();

    const decodedJWT = decodeJWT(keyBindingJWT);

    expect(decodedJWT.header).toEqual({
      alg: supportedAlgorithm.ES256,
      typ: SD_KEY_BINDING_JWT_TYP,
    });

    expect(decodedJWT.payload).toEqual({
      aud: verifierURL,
      iat: expect.any(Number),
      nonce: nonce,
      sd_hash: sdHash,
    });
  });

  it('should get KeyBindingJWT with additional header params', async () => {
    const nonce = 'nIdBbNgRqCXBl8YOkfVdg==';
    const verifierURL = 'https://valid.verifier.url';
    const sdHash = 'disclosureDigest';
    const header = {
      kid: '1b94c',
      x5c: [
        'MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB...',
        'MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJC...',
      ],
    };

    const { keyBindingJWT } = await holder.getKeyBindingJWT(verifierURL, nonce, sdHash, header);

    expect(keyBindingJWT).toBeDefined();

    const decodedJWT = decodeJWT(keyBindingJWT);

    expect(decodedJWT.header).toEqual({
      ...header,
      alg: supportedAlgorithm.ES256,
      typ: SD_KEY_BINDING_JWT_TYP,
    });

    expect(decodedJWT.payload).toEqual({
      aud: verifierURL,
      iat: expect.any(Number),
      nonce: nonce,
      sd_hash: sdHash,
    });
  });

  describe('transaction_data_hashes', () => {
    const TRANSACTION_DATA_OBJECT_1 = { type: 'qualified_esignature', credential_ids: ['cred_1'] };
    const TRANSACTION_DATA_OBJECT_2 = { type: 'qualified_certificate', credential_ids: ['cred_2'] };
    const TRANSACTION_DATA_1 = Buffer.from(JSON.stringify(TRANSACTION_DATA_OBJECT_1)).toString('base64url');
    const TRANSACTION_DATA_2 = Buffer.from(JSON.stringify(TRANSACTION_DATA_OBJECT_2)).toString('base64url');
    const EXPECTED_SHA256_HASH_1 = 'J6reCzZBvghZERFVo8pYCa-flJa92qWrc4-gGJNE6Fw';
    const EXPECTED_SHA256_HASH_2 = 'lAoNvKTMdAcq1GnyIh61xSd56hc2dp12ty_lfT7Zb68';
    const EXPECTED_SHA384_HASH_1 = 'YIBsIbWFXFojcuU_mGxN3fHsU3QK5dXS4BsLE22bTQrgdoFTVnv_mrt7jFMGER6G';

    const audience = 'https://valid.verifier.url';

    it('computes one hash per transaction_data entry, preserving order', async () => {
      const { keyBindingJWT } = await presentVCSDWithKeyBindingJWT(audience, {
        transaction_data: [TRANSACTION_DATA_1, TRANSACTION_DATA_2],
      });
      const { payload } = decodeJWT(keyBindingJWT);

      expect(payload.transaction_data_hashes).toEqual([EXPECTED_SHA256_HASH_1, EXPECTED_SHA256_HASH_2]);
      expect(payload.transaction_data_hashes_alg).toEqual('sha-256');
    });

    it('uses a non-default transactionDataHashAlg', async () => {
      const { keyBindingJWT } = await presentVCSDWithKeyBindingJWT(audience, {
        transaction_data: [TRANSACTION_DATA_1],
        transactionDataHashAlg: 'sha-384',
      });
      const { payload } = decodeJWT(keyBindingJWT);

      expect(payload.transaction_data_hashes).toEqual([EXPECTED_SHA384_HASH_1]);
      expect(payload.transaction_data_hashes_alg).toEqual('sha-384');
    });

    it('does not include transaction_data_hashes when transaction_data is not provided', async () => {
      const { keyBindingJWT } = await presentVCSDWithKeyBindingJWT(audience);
      const { payload } = decodeJWT(keyBindingJWT);

      expect(payload).toEqual({
        aud: audience,
        iat: expect.any(Number),
        nonce: expect.any(String),
        sd_hash: expect.any(String),
      });
      expect(payload).not.toHaveProperty('transaction_data_hashes');
      expect(payload).not.toHaveProperty('transaction_data_hashes_alg');
    });
  });

  it('should present VerifiableCredential SD JWT With KeyBindingJWT', async () => {
    const audience = 'https://valid.verifier.url';
    const { disclosures, keyBindingJWT, disclosedList, nonceFromVerifier } =
      await presentVCSDWithKeyBindingJWT(audience);

    expect(disclosures[0].key).toEqual(disclosedList[0].key);
    expect(disclosures[0].value).toEqual(disclosedList[0].value);
    expect(keyBindingJWT).toBeDefined();
    expect(typeof keyBindingJWT).toBe('string');

    // decode keyBindingJWT with decodeJWT
    const { header, payload, signature } = decodeJWT(keyBindingJWT);
    expect(header.alg).toEqual(supportedAlgorithm.ES256);
    expect(header.typ).toEqual(SD_KEY_BINDING_JWT_TYP);

    expect(payload.aud).toEqual(audience);
    expect(payload.nonce).toEqual(nonceFromVerifier);
    expect(payload.sd_hash).toBeDefined();

    expect(signature).toBeDefined();
  });

  it('should allow to present VC SD JWT with KeyBindingJWT when AUD is not valid URL', async () => {
    const audience = 'verifier.ssi.tir.budru.de';
    const { disclosures, keyBindingJWT, disclosedList, nonceFromVerifier } =
      await presentVCSDWithKeyBindingJWT(audience);

    expect(disclosures[0].key).toEqual(disclosedList[0].key);
    expect(disclosures[0].value).toEqual(disclosedList[0].value);
    expect(keyBindingJWT).toBeDefined();
    expect(typeof keyBindingJWT).toBe('string');

    // decode keyBindingJWT with decodeJWT
    const { header, payload, signature } = decodeJWT(keyBindingJWT);
    expect(header.alg).toEqual(supportedAlgorithm.ES256);
    expect(header.typ).toEqual(SD_KEY_BINDING_JWT_TYP);

    expect(payload.aud).toEqual(audience);
    expect(payload.nonce).toEqual(nonceFromVerifier);
    expect(payload.sd_hash).toBeDefined();

    expect(signature).toBeDefined();
  });

  describe('selectDisclosures', () => {
    it('should select disclosed information that matches the disclosures list', () => {
      const sdJWT =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZWdScUNYQmw4WU9rZlZkZz09IiwiaWF0IjoxNjk1NzgzOTgzMDQxfQ.YwgHkYEpCFRHny5L4KdnU_qARVHL2jAScodRqfF5UP50nbryqIl4i1OuaxuQKala_uYNT-e0D4xzghoxWE56SQ';
      const disclosuresList = [
        {
          disclosure: 'WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0',
          key: 'name',
          value: 'test person',
        },
      ];
      const expected =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~';
      const result = holder.selectDisclosures(sdJWT, disclosuresList);
      expect(result).toEqual(expected);
    });

    it('should throw an error if SD-JWT do not have disclosures', () => {
      const sdJWT =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA';
      const disclosuresList = [
        {
          disclosure: 'WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0',
          key: 'name',
          value: 'test person',
        },
      ];
      expect(() => holder.selectDisclosures(sdJWT, disclosuresList)).toThrow('No disclosures in SD-JWT');
    });

    it('should exclude all disclosures', () => {
      const sdJWT =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZWdScUNYQmw4WU9rZlZkZz09IiwiaWF0IjoxNjk1NzgzOTgzMDQxfQ.YwgHkYEpCFRHny5L4KdnU_qARVHL2jAScodRqfF5UP50nbryqIl4i1OuaxuQKala_uYNT-e0D4xzghoxWE56SQ';
      const disclosuresList = [];
      const expected =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~';
      const result = holder.selectDisclosures(sdJWT, disclosuresList);
      expect(result).toEqual(expected);
    });
  });

  //helper function
  async function presentVCSDWithKeyBindingJWT(
    audience: string,
    transactionDataOptions?: { transaction_data?: string[]; transactionDataHashAlg?: string },
  ) {
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
    const holder = new Holder(signer, testHasherFn);
    const issuedSDJWT =
      'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~';
    const disclosedList = [
      {
        disclosure: 'WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0',
        key: 'name',
        value: 'test person',
      },
    ];

    const nonceFromVerifier = 'nIdBbNgRqCXBl8YOkfVdg==';

    const { vcSDJWTWithkeyBindingJWT } = await holder.presentVCSDJWT(issuedSDJWT, disclosedList, {
      nonce: nonceFromVerifier,
      audience: audience,
      keyBindingVerifyCallbackFn: keyBindingVerifierCallbackFn(),
      ...transactionDataOptions,
    });

    const { disclosures, keyBindingJWT } = decodeSDJWT(vcSDJWTWithkeyBindingJWT);

    return { disclosures, keyBindingJWT, disclosedList, nonceFromVerifier };
  }
});
