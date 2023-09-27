import { JWK, importJWK } from 'jose';
import { decodeJWT } from 'sd-jwt';
import { kbVeriferCallbackFn, verifierCallbackFn } from './test-utils/helpers';
import { defaultHashAlgorithm, hasherCallbackFn } from './util';
import { Verifier } from './verifier';

describe('Verifier', () => {
  let verifier: Verifier;

  beforeEach(() => {
    verifier = new Verifier();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('verifyVerifiableCredentialSDJWT', () => {
    it('should verify VerifiableCredential SD JWT With KeyBindingJWT', async () => {
      const { vcSDJWTWithkeyBindingJWT, nonce } = {
        vcSDJWTWithkeyBindingJWT:
          'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZWdScUNYQmw4WU9rZlZkZz09IiwiaWF0IjoxNjk1NzgzOTgzMDQxfQ.YwgHkYEpCFRHny5L4KdnU_qARVHL2jAScodRqfF5UP50nbryqIl4i1OuaxuQKala_uYNT-e0D4xzghoxWE56SQ',
        nonce: 'nIdBbNegRqCXBl8YOkfVdg==',
      };

      console.log('vcSDJWTWithkeyBindingJWT: ' + vcSDJWTWithkeyBindingJWT);
      console.log('nonce: ' + nonce);

      const issuerPubKey = await importJWK({
        crv: 'Ed25519',
        x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
        kty: 'OKP',
      });

      const result = await verifier.verifyVerifiableCredentialSDJWT(
        vcSDJWTWithkeyBindingJWT,
        verifierCallbackFn(issuerPubKey),
        hasherCallbackFn(defaultHashAlgorithm),
        kbVeriferCallbackFn('https://valid.verifier.url', nonce),
      );
      console.log(result);
    });
  });

  describe('fetchIssuerPublicKeyFromIss', () => {
    const sdJwtVC =
      'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA';
    const issuerPath = 'jwt-issuer/user/1234';

    it('should fetch issuer public key JWK from jwks_uri', async () => {
      const jwt = decodeJWT(sdJwtVC);
      const wellKnownPath = `.well-known/${issuerPath}`;
      const url = new URL(jwt.payload.iss);
      const baseUrl = `${url.protocol}//${url.host}`;
      const issuerUrl = `${baseUrl}/${wellKnownPath}`;
      const jwksUri = `${issuerUrl}/my_public_keys.jwks`;
      const jwks = {
        keys: [
          {
            kty: 'RSA',
            kid: 'test-key',
            n: 'test-n',
            e: 'AQAB',
          },
        ],
      };
      const jwksResponseJson = {
        issuer: jwt.payload.iss,
        jwks_uri: jwksUri,
      };
      const expectedJWK: JWK = {
        kty: 'RSA',
        kid: 'test-key',
        n: 'test-n',
        e: 'AQAB',
      };

      (global as any).fetch = jest.fn().mockImplementation((url: string) => {
        if (url === issuerUrl) {
          return Promise.resolve({
            json: () => Promise.resolve(jwksResponseJson),
          });
        } else if (url === jwksUri) {
          return Promise.resolve({
            json: () => Promise.resolve(jwks),
          });
        } else {
          throw new Error(`Unexpected URL: ${url}`);
        }
      });

      const result = await verifier.fetchIssuerPublicKeyFromIss(sdJwtVC, issuerPath);

      expect(fetch).toHaveBeenCalledTimes(2);
      expect(fetch).toHaveBeenNthCalledWith(1, issuerUrl);
      expect(fetch).toHaveBeenNthCalledWith(2, jwksUri);
      expect(result).toEqual(expectedJWK);
    });

    it('should fetch issuer public key JWK from jwks', async () => {
      const jwt = decodeJWT(sdJwtVC);
      const wellKnownPath = `.well-known/${issuerPath}`;
      const url = new URL(jwt.payload.iss);
      const baseUrl = `${url.protocol}//${url.host}`;
      const issuerUrl = `${baseUrl}/${wellKnownPath}`;
      const jwks = {
        keys: [
          {
            kty: 'RSA',
            kid: 'test-key',
            n: 'test-n',
            e: 'AQAB',
          },
        ],
      };
      const responseJson = {
        issuer: jwt.payload.iss,
        jwks: jwks,
      };
      const expectedJWK: JWK = {
        kty: 'RSA',
        kid: 'test-key',
        n: 'test-n',
        e: 'AQAB',
      };

      (global as any).fetch = jest.fn().mockImplementation((url: string) => {
        if (url === issuerUrl) {
          return Promise.resolve({
            json: () => Promise.resolve(responseJson),
          });
        } else {
          throw new Error(`Unexpected URL: ${url}`);
        }
      });

      const result = await verifier.fetchIssuerPublicKeyFromIss(sdJwtVC, issuerPath);

      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(issuerUrl);
      expect(result).toEqual(expectedJWK);
    });

    it('should throw an error if issuer response is not found', async () => {
      const jwt = decodeJWT(sdJwtVC);
      const wellKnownPath = `.well-known/${issuerPath}`;
      const url = new URL(jwt.payload.iss);
      const baseUrl = `${url.protocol}//${url.host}`;
      const issuerUrl = `${baseUrl}/${wellKnownPath}`;

      (global as any).fetch = jest.fn().mockResolvedValueOnce({
        json: () => Promise.resolve(null),
      });

      await expect(verifier.fetchIssuerPublicKeyFromIss(sdJwtVC, issuerPath)).rejects.toThrow(
        'Issuer response not found',
      );
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(issuerUrl);
    });

    it('should throw an error if issuer response does not contain the correct issuer', async () => {
      const jwt = decodeJWT(sdJwtVC);
      const wellKnownPath = `.well-known/${issuerPath}`;
      const url = new URL(jwt.payload.iss);
      const baseUrl = `${url.protocol}//${url.host}`;
      const issuerUrl = `${baseUrl}/${wellKnownPath}`;
      const responseJson = {
        issuer: 'wrong-issuer',
      };

      (global as any).fetch = jest.fn().mockResolvedValueOnce({
        json: () => Promise.resolve(responseJson),
      });

      await expect(verifier.fetchIssuerPublicKeyFromIss(sdJwtVC, issuerPath)).rejects.toThrow(
        'Issuer response does not contain the correct issuer',
      );
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(issuerUrl);
    });

    it('should throw an error if issuer public key JWK is not found', async () => {
      const jwt = decodeJWT(sdJwtVC);
      const wellKnownPath = `.well-known/${issuerPath}`;
      const url = new URL(jwt.payload.iss);
      const baseUrl = `${url.protocol}//${url.host}`;
      const issuerUrl = `${baseUrl}/${wellKnownPath}`;
      const responseJson = {
        issuer: jwt.payload.iss,
        jwks: {
          keys: [],
        },
      };

      (global as any).fetch = jest.fn().mockResolvedValueOnce({
        json: () => Promise.resolve(responseJson),
      });

      await expect(verifier.fetchIssuerPublicKeyFromIss(sdJwtVC, issuerPath)).rejects.toThrow(
        'Issuer public key JWK not found',
      );
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(issuerUrl);
    });

    it('should throw an error if issuer response does not contain jwks or jwks_uri', async () => {
      const jwt = decodeJWT(sdJwtVC);
      const wellKnownPath = `.well-known/${issuerPath}`;
      const url = new URL(jwt.payload.iss);
      const baseUrl = `${url.protocol}//${url.host}`;
      const issuerUrl = `${baseUrl}/${wellKnownPath}`;
      const responseJson = {
        issuer: jwt.payload.iss,
      };

      (global as any).fetch = jest.fn().mockResolvedValueOnce({
        json: () => Promise.resolve(responseJson),
      });

      await expect(verifier.fetchIssuerPublicKeyFromIss(sdJwtVC, issuerPath)).rejects.toThrow(
        'Issuer response does not contain jwks or jwks_uri',
      );
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(issuerUrl);
    });

    it('should throw an error if jwks_uri response does not contain the correct issuer', async () => {
      const jwt = decodeJWT(sdJwtVC);
      const wellKnownPath = `.well-known/${issuerPath}`;
      const url = new URL(jwt.payload.iss);
      const baseUrl = `${url.protocol}//${url.host}`;
      const issuerUrl = `${baseUrl}/${wellKnownPath}`;
      const jwksUri = `${issuerUrl}/jwks_uri`;
      const jwksResponseJson = {
        issuer: 'wrong-issuer',
        jwks_uri: jwksUri,
      };

      (global as any).fetch = jest.fn().mockResolvedValueOnce({
        json: () => Promise.resolve(jwksResponseJson),
      });

      await expect(verifier.fetchIssuerPublicKeyFromIss(sdJwtVC, issuerPath)).rejects.toThrow(
        'Issuer response does not contain the correct issuer',
      );
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(fetch).toHaveBeenCalledWith(issuerUrl);
    });
  });
});
