import { Hasher } from '@meeco/sd-jwt';
import { importJWK } from 'jose';
import { hasherCallbackFn, kbVeriferCallbackFn, verifierCallbackFn } from './test-utils/helpers';
import { ValidTypValues, defaultHashAlgorithm } from './util';
import { Verifier } from './verifier';

describe('Verifier', () => {
  let verifier: Verifier;

  beforeEach(() => {
    verifier = new Verifier();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('verifyVCDJWT', () => {
    it('should verify VerifiableCredential SD JWT With KeyBindingJWT (vc+sd-jwt typ)', async () => {
      const claims = {
        iat: 1695682408857,
        cnf: {
          jwk: {
            kty: 'EC',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
            crv: 'P-256',
          },
        },
        iss: 'https://valid.issuer.url',
        type: 'VerifiableCredential',
        status: { idx: 'statusIndex', uri: 'https://valid.status.url' },
        person: { name: 'test person', age: 25 },
      };

      const { vcSDJWTWithkeyBindingJWT, nonce } = {
        vcSDJWTWithkeyBindingJWT:
          'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZ1JxQ1hCbDhZT2tmVmRnPT0iLCJzZF9oYXNoIjoiTHdvOXZaMHc5SlVkZFlNdEVrc3JVYWc4TnRtY05JNGdFT3JhbzVYT1R6SSIsImlhdCI6MTcwNzE0NzYxNjk3MX0._rdKs3oVlxu6rGtbiBxP69Ammlc4OV6IPvQa9EVI6JUis3Vf5xOofS7xkJDeM5Q8rg00_vQqyQ21eYapyvLMSA',
        nonce: 'nIdBbNgRqCXBl8YOkfVdg==',
      };

      const issuerPubKey = await importJWK({
        crv: 'Ed25519',
        x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
        kty: 'OKP',
      });

      const vcSDJWTWithoutKeyBinding: string = vcSDJWTWithkeyBindingJWT.slice(
        0,
        vcSDJWTWithkeyBindingJWT.lastIndexOf('~') + 1,
      );
      const hasher: Hasher = hasherCallbackFn(defaultHashAlgorithm);
      const sdJwtHash: string = hasher(vcSDJWTWithoutKeyBinding);

      const result = await verifier.verifyVCSDJWT(
        vcSDJWTWithkeyBindingJWT,
        verifierCallbackFn(issuerPubKey),
        hasherCallbackFn(defaultHashAlgorithm),
        kbVeriferCallbackFn('https://valid.verifier.url', nonce, sdJwtHash),
      );
      expect(result).toEqual(claims);
    });

    it('should verify VerifiableCredential SD JWT With KeyBindingJWT (dc+sd-jwt typ)', async () => {
      const claims = {
        iat: 1748320939,
        cnf: {
          jwk: {
            kty: 'EC',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
            crv: 'P-256',
          },
        },
        iss: 'http://issuer.url/jwks',
        vct: 'https://credentials.example.com/identity_credential',
        person: { name: 'test person', age: 25 },
      };

      const dcSdJwtWithKb =
        'eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3NDgzMjA5MzksImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHA6Ly9pc3N1ZXIudXJsL2p3a3MiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJfc2QiOlsiYnY3ZmZiaWRnV3JnR19YNTlBUjZYZXBOb3I1RjNZeTNxZ01IOUZHbmlaZyJdLCJfc2RfYWxnIjoic2hhMjU2In0.kngQbIsVNEA03Pif5om5fvnt9C2Sz83c-XblGUAWDyseGYqhSu5nwrdhpB1Gc-WaKrtjFMkFVouxQTGjsWApuA~WyJ6bkZLdk5CZnh4dDNlVDJVIiwicGVyc29uIix7Im5hbWUiOiJ0ZXN0IHBlcnNvbiIsImFnZSI6MjV9XQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZ1JxQ1hCbDhZT2tmVmRnPT0iLCJzZF9oYXNoIjoiUUJiNVdud2FTTTVjODEtNzhIN3JWS0ZKYVl2QlZ0YWFoRTBOX09MNlgtSSIsImlhdCI6MTc0ODMyMTAzMn0.XwQE8BY-i1UMihAuwushw5lc1pUfjPvlgAUrcqIGvKNYxBTMeiMeDr2DIUjIFqUqMsK3o7eYcd4jPP2DWU56cQ';
      const nonce = 'nIdBbNgRqCXBl8YOkfVdg==';

      const issuerPubKey = await importJWK({
        kty: 'EC',
        x: 'MRbP5zJSo9CxUla-ThmzvwUl_3f76bCwrnuQOPK54dQ',
        y: 't1VIetPpyi7rV8ARvaas1VmPmgd6YGo1e-Z5aqedwEU',
        crv: 'P-256',
      });

      const vcSDJWTWithoutKeyBinding: string = dcSdJwtWithKb.slice(0, dcSdJwtWithKb.lastIndexOf('~') + 1);
      const hasher: Hasher = hasherCallbackFn(defaultHashAlgorithm);
      const sdJwtHash: string = hasher(vcSDJWTWithoutKeyBinding);

      const result = await verifier.verifyVCSDJWT(
        dcSdJwtWithKb,
        verifierCallbackFn(issuerPubKey),
        hasherCallbackFn(defaultHashAlgorithm),
        kbVeriferCallbackFn('https://valid.verifier.url', nonce, sdJwtHash),
      );
      expect(result).toEqual(claims);
    });

    it('should verify VerifiableCredential SD JWT Without KeyBindingJWT (vc+sd-jwt typ)', async () => {
      const claims = {
        iat: 1695682408857,
        cnf: {
          jwk: {
            kty: 'EC',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
            crv: 'P-256',
          },
        },
        iss: 'https://valid.issuer.url',
        type: 'VerifiableCredential',
        status: { idx: 'statusIndex', uri: 'https://valid.status.url' },
        person: { name: 'test person', age: 25 },
      };

      const vcSDJWTWithOutkeyBindingJWT =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~';

      const issuerPubKey = await importJWK({
        crv: 'Ed25519',
        x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
        kty: 'OKP',
      });

      const result = await verifier.verifyVCSDJWT(
        vcSDJWTWithOutkeyBindingJWT,
        verifierCallbackFn(issuerPubKey),
        hasherCallbackFn(defaultHashAlgorithm),
      );
      expect(result).toEqual(claims);
    });

    it('should verify VerifiableCredential SD JWT Without KeyBindingJWT (dc+sd-jwt typ)', async () => {
      const claims = {
        iat: 1748320939,
        cnf: {
          jwk: {
            kty: 'EC',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
            crv: 'P-256',
          },
        },
        iss: 'http://issuer.url/jwks',
        vct: 'https://credentials.example.com/identity_credential',
        person: { name: 'test person', age: 25 },
      };

      const dcSdJwtWithoutKb =
        'eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3NDgzMjA5MzksImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHA6Ly9pc3N1ZXIudXJsL2p3a3MiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJfc2QiOlsiYnY3ZmZiaWRnV3JnR19YNTlBUjZYZXBOb3I1RjNZeTNxZ01IOUZHbmlaZyJdLCJfc2RfYWxnIjoic2hhMjU2In0.kngQbIsVNEA03Pif5om5fvnt9C2Sz83c-XblGUAWDyseGYqhSu5nwrdhpB1Gc-WaKrtjFMkFVouxQTGjsWApuA~WyJ6bkZLdk5CZnh4dDNlVDJVIiwicGVyc29uIix7Im5hbWUiOiJ0ZXN0IHBlcnNvbiIsImFnZSI6MjV9XQ~';

      const issuerPubKey = await importJWK({
        kty: 'EC',
        x: 'MRbP5zJSo9CxUla-ThmzvwUl_3f76bCwrnuQOPK54dQ',
        y: 't1VIetPpyi7rV8ARvaas1VmPmgd6YGo1e-Z5aqedwEU',
        crv: 'P-256',
      });

      const result = await verifier.verifyVCSDJWT(
        dcSdJwtWithoutKb,
        verifierCallbackFn(issuerPubKey),
        hasherCallbackFn(defaultHashAlgorithm),
      );
      expect(result).toEqual(claims);
    });

    it('should throw an error for invalid typ header', async () => {
      const invalidTypJwt = 'eyJ0eXAiOiJpbnZhbGlkK3R5cCIsImFsZyI6IkVkRFNBIn0.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl';
      const issuerPubKey = await importJWK({
        crv: 'Ed25519',
        x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
        kty: 'OKP',
      });

      await expect(() =>
        verifier.verifyVCSDJWT(invalidTypJwt, verifierCallbackFn(issuerPubKey), hasherCallbackFn(defaultHashAlgorithm)),
      ).rejects.toThrow(
        `Invalid typ header. Expected one of ${ValidTypValues.VCSDJWT}, ${ValidTypValues.DCSDJWT}, received invalid+typ`,
      );
    });

    it('should throw an error if keybinding jwt present and kbVeriferCallbackFn is not provided', async () => {
      const vcSDJWTWithkeyBindingJWT =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZWdScUNYQmw4WU9rZlZkZz09IiwiaWF0IjoxNjk1NzgzOTgzMDQxfQ.YwgHkYEpCFRHny5L4KdnU_qARVHL2jAScodRqfF5UP50nbryqIl4i1OuaxuQKala_uYNT-e0D4xzghoxWE56SQ';

      const issuerPubKey = await importJWK({
        crv: 'Ed25519',
        x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
        kty: 'OKP',
      });

      await expect(() =>
        verifier.verifyVCSDJWT(
          vcSDJWTWithkeyBindingJWT,
          verifierCallbackFn(issuerPubKey),
          hasherCallbackFn(defaultHashAlgorithm),
        ),
      ).rejects.toThrow('Missing key binding verifier callback function');
    });

    it('should throw an error if keybinding jwt do not have aud, nonce or iat', async () => {
      const { vcSDJWTWithkeyBindingJWT, nonce } = {
        vcSDJWTWithkeyBindingJWT:
          'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsImlhdCI6MTY5NTc4Mzk4MzA0MX0.YwgHkYEpCFRHny5L4KdnU_qARVHL2jAScodRqfF5UP50nbryqIl4i1OuaxuQKala_uYNT-e0D4xzghoxWE56SQ',
        nonce: 'nIdBbNegRqCXBl8YOkfVdg==',
      };
      const issuerPubKey = await importJWK({
        crv: 'Ed25519',
        x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
        kty: 'OKP',
      });

      const vcSDJWTWithoutKeyBinding: string = vcSDJWTWithkeyBindingJWT.slice(
        0,
        vcSDJWTWithkeyBindingJWT.lastIndexOf('~') + 1,
      );
      const hasher: Hasher = hasherCallbackFn(defaultHashAlgorithm);
      const sdJwtHash: string = hasher(vcSDJWTWithoutKeyBinding);

      await expect(() =>
        verifier.verifyVCSDJWT(
          vcSDJWTWithkeyBindingJWT,
          verifierCallbackFn(issuerPubKey),
          hasherCallbackFn(defaultHashAlgorithm),
          kbVeriferCallbackFn('https://valid.verifier.url', nonce, sdJwtHash),
        ),
      ).rejects.toThrow('Missing aud, nonce, iat or sd_hash in key binding JWT');
    });
  });
});
