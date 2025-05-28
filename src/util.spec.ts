import { decodeJWT, JWK, Hasher as SDJWTHasher, SDJWTPayload } from '@meeco/sd-jwt';
import * as crypto from 'crypto';
import { SDJWTVCError } from './errors';
import {
  extractEmbeddedTypeMetadata,
  fetchTypeMetadataFromUrl,
  getIssuerPublicKeyFromWellKnownURI,
  isValidUrl,
} from './util';

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

describe('extractEmbeddedTypeMetadata', () => {
  it('should return null if vctm header is not present', () => {
    const sdJwtVC = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl'; // No vctm
    expect(extractEmbeddedTypeMetadata(sdJwtVC)).toBeNull();
  });

  it('should return null for a malformed JWS header', () => {
    const sdJwtVC = 'malformedJWS.payload.signature';
    expect(extractEmbeddedTypeMetadata(sdJwtVC)).toBeNull();
  });

  it('should throw an error if vctm is present but not an array', () => {
    // JWS with unprotected header: { "vctm": "not-an-array" }
    // Header: eyJ2Y3RtIjoibm90LWFuLWFycmF5In0 (base64url of {"vctm":"not-an-array"})
    const sdJwtVC = 'eyJ2Y3RtIjoibm90LWFuLWFycmF5In0.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl';
    expect(() => extractEmbeddedTypeMetadata(sdJwtVC)).toThrow(
      new SDJWTVCError('vctm in unprotected header must be an array'),
    );
  });

  it('should throw an error if vctm contains invalid base64url data', () => {
    // JWS with unprotected header: { "vctm": ["invalid-b64url!"] }
    // Header: eyJ2Y3RtIjpbImludmFsaWQtYjY0dXJsISJdfQ (base64url of {"vctm":["invalid-b64url!"]})
    const sdJwtVC = 'eyJ2Y3RtIjpbImludmFsaWQtYjY0dXJsISJdfQ.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl';
    expect(() => extractEmbeddedTypeMetadata(sdJwtVC)).toThrow(SDJWTVCError);
  });

  it('should correctly decode and return type metadata documents', () => {
    const doc1 = { type: 'doc1', data: 'test1' };
    const doc2 = { type: 'doc2', data: 'test2' };
    const encodedDoc1 = Buffer.from(JSON.stringify(doc1)).toString('base64url');
    const encodedDoc2 = Buffer.from(JSON.stringify(doc2)).toString('base64url');
    // Constructing the JWS with the vctm in the *unprotected* header part is tricky directly in a string literal
    // as it's part of the signed JWS structure. For testing, we simulate a JWS where the
    // unprotected header part (if it were separate, which it isn't in compact JWS) would contain vctm.
    // The function `decodeProtectedHeader` correctly decodes the *first* part of a JWS (the protected header).
    // If `vctm` is intended to be in an *unprotected* header, the `decodeJWT` from `@meeco/sd-jwt` might expose it differently,
    // or the JWS needs to be constructed in a specific way (e.g., using General JWS JSON Serialization).
    // For this test, we'll assume the `vctm` is part of the main JWS header, decodable by `decodeProtectedHeader`.
    const headerWithVctm = { vctm: [encodedDoc1, encodedDoc2] };
    const base64UrlEncodedHeader = Buffer.from(JSON.stringify(headerWithVctm)).toString('base64url');
    const sdJwtVC = `${base64UrlEncodedHeader}.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl`;

    const result = extractEmbeddedTypeMetadata(sdJwtVC);
    expect(result).toEqual([doc1, doc2]);
  });

  it('should return empty array if vctm is an empty array', () => {
    // JWS with unprotected header: { "vctm": [] }
    // Header: eyJ2Y3RtIjpbXX0 (base64url of {"vctm":[]})
    const sdJwtVC = 'eyJ2Y3RtIjpbXX0.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl';
    const result = extractEmbeddedTypeMetadata(sdJwtVC);
    expect(result).toEqual([]);
  });
});

describe('fetchTypeMetadataFromUrl', () => {
  const mockPayloadBase: SDJWTPayload = {
    iss: 'https://issuer.example.com',
    sub: 'user123',
    iat: Date.now(),
    exp: Date.now() + 3600000,
  };

  const mockTypeMetadata = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'CustomType'],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Bachelor of Science and Arts',
      },
    },
  };

  // Define mockHasher as a synchronous function returning string
  const mockHasher: SDJWTHasher = jest.fn((data: string): string => {
    return crypto.createHash('sha256').update(data).digest('base64url');
  });

  beforeEach(() => {
    // Resets all mocks, including their call counts
    jest.resetAllMocks();
    (global as any).fetch = jest.fn();
  });

  it('should return null if vct is not a string', async () => {
    const payload = { ...mockPayloadBase, vct: 12345 as any };
    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('should return null if vct is not an HTTPS URL', async () => {
    const payload = { ...mockPayloadBase, vct: 'http://example.com/metadata' };
    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('should return null if vct is not a valid URL', async () => {
    const payload = { ...mockPayloadBase, vct: 'https://invalid url' }; // relies on util.isValidUrl
    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('should fetch and return type metadata for a valid vct URL', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const payload = { ...mockPayloadBase, vct: vctUrl };
    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(JSON.stringify(mockTypeMetadata)),
    });

    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toEqual(mockTypeMetadata);
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should return null if fetching metadata fails (network error)', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const payload = { ...mockPayloadBase, vct: vctUrl };
    (global as any).fetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    });

    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toBeNull();
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should return null if fetched content is not valid JSON', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const payload = { ...mockPayloadBase, vct: vctUrl };
    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve('this is not json'),
    });

    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toBeNull();
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should perform integrity check if vct#integrity and hasher are provided', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const contentHash = mockHasher(rawContent); // mockHasher is sync now
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': contentHash };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear(); // Clear calls from contentHash generation

    const result = await fetchTypeMetadataFromUrl(payload, { hasher: mockHasher });
    expect(result).toEqual(mockTypeMetadata);
    expect(mockHasher).toHaveBeenCalledWith(rawContent);
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should perform integrity check with algorithm prefix in vct#integrity', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const contentHash = mockHasher(rawContent); // mockHasher is sync
    const integrityClaim = `sha256-${contentHash}`;
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': integrityClaim };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear();

    const result = await fetchTypeMetadataFromUrl(payload, { hasher: mockHasher });
    expect(result).toEqual(mockTypeMetadata);
    expect(mockHasher).toHaveBeenCalledWith(rawContent);
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should throw SDJWTVCError if integrity check fails', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    // mockHasher will produce a specific hash for rawContent.
    // wrongHash is different, so the check should fail.
    const wrongHash = 'totally-different-hash-value';
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': wrongHash };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear();

    await expect(fetchTypeMetadataFromUrl(payload, { hasher: mockHasher })).rejects.toThrow(SDJWTVCError);
    expect(mockHasher).toHaveBeenCalledWith(rawContent);
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should throw SDJWTVCError if integrity check fails with prefixed hash', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const calculatedCorrectHash = mockHasher(rawContent);
    const wrongHashClaim = 'sha256-totally-different-hash-value'; // Claim in JWT
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': wrongHashClaim };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear();

    await expect(fetchTypeMetadataFromUrl(payload, { hasher: mockHasher })).rejects.toThrow(
      `Type Metadata integrity check failed for ${vctUrl}. Expected hash totally-different-hash-value (derived from ${wrongHashClaim}), got ${calculatedCorrectHash}.`,
    );
    expect(mockHasher).toHaveBeenCalledWith(rawContent);
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should not perform integrity check if hasher is not provided, even if vct#integrity is present', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const contentHash = mockHasher(rawContent); // Generate hash for payload
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': contentHash };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear(); // Clear calls from contentHash generation

    const result = await fetchTypeMetadataFromUrl(payload); // No hasher in options
    expect(result).toEqual(mockTypeMetadata);
    expect(mockHasher).not.toHaveBeenCalled(); // fetchTypeMetadataFromUrl should not call it
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should not perform integrity check if vct#integrity is not present, even if hasher is provided', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const payload = { ...mockPayloadBase, vct: vctUrl }; // No vct#integrity

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear();

    const result = await fetchTypeMetadataFromUrl(payload, { hasher: mockHasher });
    expect(result).toEqual(mockTypeMetadata);
    expect(mockHasher).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should re-throw SDJWTVCError if integrity check itself throws it (e.g. hasher misbehaves)', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const integrityClaim = 'sha256-somehash';
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': integrityClaim };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });

    (mockHasher as jest.Mock).mockImplementationOnce(() => {
      throw new SDJWTVCError('Deliberate SDJWTVCError from hasher');
    });

    await expect(fetchTypeMetadataFromUrl(payload, { hasher: mockHasher })).rejects.toThrow(
      new SDJWTVCError('Deliberate SDJWTVCError from hasher'),
    );
  });

  it('should return null and warn for general errors during fetch operation', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const payload = { ...mockPayloadBase, vct: vctUrl };
    const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    (global as any).fetch.mockRejectedValueOnce(new Error('Network failure'));

    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toBeNull();
    expect(fetch).toHaveBeenCalledWith(vctUrl);
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining(`Error fetching Type Metadata from ${vctUrl}: Network failure`),
    );
    consoleWarnSpy.mockRestore();
  });
});

// Ensure existing isValidUrl tests are present and correct
describe('isValidUrl', () => {
  it('should return true for valid URLs', () => {
    expect(isValidUrl('https://example.com')).toBe(true);
    expect(isValidUrl('http://localhost:3000/path?query=value#hash')).toBe(true);
    expect(isValidUrl('https://sub.domain.example.co.uk/path.html')).toBe(true);
  });

  it('should return false for invalid URLs', () => {
    expect(isValidUrl('not a url')).toBe(false);
    expect(isValidUrl('example.com')).toBe(false); // Missing scheme
    expect(isValidUrl('htp://example.com')).toBe(false); // Typo in scheme
    expect(isValidUrl('https//example.com')).toBe(false); // Missing colon
    expect(isValidUrl('')).toBe(false);
    expect(isValidUrl(' https://example.com')).toBe(false); // Leading space
    expect(isValidUrl('https://example.com/ path')).toBe(false); // Space in path
  });
});
