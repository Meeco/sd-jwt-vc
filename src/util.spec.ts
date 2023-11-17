import { JWK, decodeJWT } from '@meeco/sd-jwt';
import { getIssuerPublicKeyFromWellKnownURI } from './util';

describe('getIssuerPublicKeyFromIss', () => {
  const sdJwtVC =
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA';
  const issuerPath = 'jwt-issuer/user/1234';

  it('should get issuer public key JWK from jwks_uri', async () => {
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

    const result = await getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath);

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenNthCalledWith(1, issuerUrl);
    expect(fetch).toHaveBeenNthCalledWith(2, jwksUri);
    expect(result).toEqual(expectedJWK);
  });

  it('should get issuer public key JWK from jwks', async () => {
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

    const result = await getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath);

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

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow('Issuer response not found');
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

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
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

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
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

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
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

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(issuerUrl);
  });

  it('should throw an error if well-known retrun empty response', async () => {
    const jwt = decodeJWT(sdJwtVC);
    const wellKnownPath = `.well-known/${issuerPath}`;
    const url = new URL(jwt.payload.iss);
    const baseUrl = `${url.protocol}//${url.host}`;
    const issuerUrl = `${baseUrl}/${wellKnownPath}`;
    const jwksResponseJson = {};

    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      json: () => Promise.resolve(jwksResponseJson),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(issuerUrl);
  });

  it('should throw an error if well-known retrun 404', async () => {
    const jwt = decodeJWT(sdJwtVC);
    const wellKnownPath = `.well-known/${issuerPath}`;
    const url = new URL(jwt.payload.iss);
    const baseUrl = `${url.protocol}//${url.host}`;
    const issuerUrl = `${baseUrl}/${wellKnownPath}`;
    const jwksResponseJson = {
      status: 404,
      json: () => Promise.reject(new Error('Issuer response not found')),
    };

    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      json: () => Promise.resolve(jwksResponseJson),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      "The response from the issuer's well-known URI does not match the expected issuer",
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(issuerUrl);
  });

  it('should throw an error if well-known retrun invalid response', async () => {
    const jwt = decodeJWT(sdJwtVC);
    const wellKnownPath = `.well-known/${issuerPath}`;
    const url = new URL(jwt.payload.iss);
    const baseUrl = `${url.protocol}//${url.host}`;
    const issuerUrl = `${baseUrl}/${wellKnownPath}`;

    (global as any).fetch = jest.fn().mockResolvedValueOnce({
      invalid: () =>
        Promise.resolve(
          'Failed to fetch or parse the response from https://valid.issuer.url/.well-known/jwt-issuer/user/1234 as JSON. Error: response.json is not a function',
        ),
    });

    await expect(getIssuerPublicKeyFromWellKnownURI(sdJwtVC, issuerPath)).rejects.toThrow(
      'Failed to fetch or parse the response from https://valid.issuer.url/.well-known/jwt-issuer/user/1234 as JSON. Error: response.json is not a function',
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(issuerUrl);
  });
});
