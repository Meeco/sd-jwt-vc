import { JWK, decodeJWT } from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors';
import { getIssuerPublicKeyFromWellKnownURI } from './util';

describe('getIssuerPublicKeyFromIss', () => {
  const sdJwtVC =
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA';
  const issuerPath = 'user/1234';

  const jwt = decodeJWT(sdJwtVC);
  const url = new URL(jwt.payload.iss);

  const baseUrl = `${url.protocol}//${url.host}`;
  const jwtIssuerWellKnownUrl = `${baseUrl}/.well-known/jwt-vc-issuer/${issuerPath}`;
  const jwtIssuerWellKnownFallbackUrl = `${baseUrl}/.well-known/jwt-issuer/${issuerPath}`;
  const issuerUrl = `${baseUrl}/${issuerPath}`;
  const jwksUri = `${issuerUrl}/my_public_keys.jwks`;

  it('should get issuer public key JWK from jwks_uri', async () => {
    const expectedJWK: JWK = {
      kty: 'RSA',
      kid: 'test-key',
      n: 'test-n',
      e: 'AQAB',
    };

    (global as any).fetch = jest.fn().mockImplementation((url: string) => {
      if (url === jwtIssuerWellKnownUrl) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              issuer: jwt.payload.iss,
              jwks_uri: jwksUri,
            }),
        });
      } else if (url === jwksUri) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              keys: [
                {
                  kty: 'RSA',
                  kid: 'test-key',
                  n: 'test-n',
                  e: 'AQAB',
                },
              ],
            }),
        });
      } else {
        throw new SDJWTVCError(`Unexpected URL: ${url}`);
      }
    });

    const result = await getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath);

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenNthCalledWith(1, jwtIssuerWellKnownUrl);
    expect(fetch).toHaveBeenNthCalledWith(2, jwksUri);
    expect(result).toEqual(expectedJWK);
  });

  it('should get issuer public key JWK from jwks', async () => {
    const expectedJWK: JWK = {
      kty: 'RSA',
      kid: 'test-key',
      n: 'test-n',
      e: 'AQAB',
    };

    (global as any).fetch = jest.fn().mockImplementation((url: string) => {
      if (url === jwtIssuerWellKnownUrl) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              issuer: jwt.payload.iss,
              jwks: {
                keys: [
                  {
                    kty: 'RSA',
                    kid: 'test-key',
                    n: 'test-n',
                    e: 'AQAB',
                  },
                ],
              },
            }),
        });
      } else {
        throw new SDJWTVCError(`Unexpected URL: ${url}`);
      }
    });

    const result = await getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath);

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
    expect(result).toEqual(expectedJWK);
  });

  it('should get issuer public keys from a fallback endpoint', async () => {
    const expectedJWK: JWK = {
      kty: 'RSA',
      kid: 'test-key',
      n: 'test-n',
      e: 'AQAB',
    };

    (global as any).fetch = jest.fn().mockImplementation((url: string) => {
      if (url === jwtIssuerWellKnownUrl) {
        return Promise.resolve({
          ok: false,
          json: () => Promise.reject(new SDJWTVCError('Issuer response not found')),
        });
      }

      if (url === jwtIssuerWellKnownFallbackUrl) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              issuer: jwt.payload.iss,
              jwks: {
                keys: [
                  {
                    kty: 'RSA',
                    kid: 'test-key',
                    n: 'test-n',
                    e: 'AQAB',
                  },
                ],
              },
            }),
        });
      }

      throw new SDJWTVCError(`Unexpected URL: ${url}`);
    });

    const result = await getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath);

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownFallbackUrl);
    expect(result).toEqual(expectedJWK);
  });

  it('should throw an error if issuer response is not found', async () => {
    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow('Issuer response not found');

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
  });

  it('should throw an error if issuer response does not contain the correct issuer', async () => {
    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          issuer: 'wrong-issuer',
        }),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
    );

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
  });

  it('should throw an error if issuer public key JWK is not found', async () => {
    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          issuer: jwt.payload.iss,
          jwks: {
            keys: [],
          },
        }),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      'Issuer public key JWK not found',
    );

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
  });

  it('should throw an error if issuer response does not contain jwks or jwks_uri', async () => {
    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          issuer: jwt.payload.iss,
        }),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      'Issuer response does not contain jwks or jwks_uri',
    );

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
  });

  it('should throw an error if jwks_uri response does not contain the correct issuer', async () => {
    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          issuer: 'wrong-issuer',
          jwks_uri: jwksUri,
        }),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
    );

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
  });

  it('should throw an error if well-known returns empty response', async () => {
    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({}),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
    );

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
  });

  it('throws error if issuer from well-known file does not match one inside the sd-jwt', async () => {
    (global as any).fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          issuer: 'http://some.other/issuer',
          jwks: {
            keys: [
              {
                kty: 'RSA',
                kid: 'test-key',
                n: 'test-n',
                e: 'AQAB',
              },
            ],
          },
        }),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
    );

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
  });

  it('should throw an error if well-known calls return errors', async () => {
    (global as any).fetch = jest
      .fn()
      .mockResolvedValue({
        ok: false,
        json: () => Promise.resolve({ message: 'not found' }),
      })
      .mockResolvedValue({
        ok: false,
        json: () => Promise.resolve({ message: 'internal server error' }),
      });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      'Failed to fetch and parse the response from https://valid.issuer.url/.well-known/jwt-vc-issuer/user/1234 as JSON. Error: {"message":"internal server error"}. Fallback fetch and parse the response from https://valid.issuer.url/.well-known/jwt-issuer/user/1234 failed as well. Error: {"message":"internal server error"}.',
    );

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownUrl);
    expect(fetch).toHaveBeenCalledWith(jwtIssuerWellKnownFallbackUrl);
  });
});
