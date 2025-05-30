import { decodeJWT, JWK, Hasher as SDJWTHasher, SDJWTPayload } from '@meeco/sd-jwt';
import * as crypto from 'crypto';
import { SDJWTVCError } from './errors';
import { extractEmbeddedTypeMetadata, fetchTypeMetadataFromUrl, getIssuerPublicKeyFromWellKnownURI } from './util';

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
    const sdJwtVC = 'eyJ2Y3RtIjoibm90LWFuLWFycmF5In0.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl';
    expect(() => extractEmbeddedTypeMetadata(sdJwtVC)).toThrow(
      new SDJWTVCError('vctm in unprotected header must be an array'),
    );
  });

  it('should throw an error if vctm contains invalid base64url data', () => {
    // JWS with unprotected header: { "vctm": ["invalid-b64url!"] }
    // Header: eyJ2Y3RtIjpbImludmFsaWQtYjY0dXJsISJdfQ (base64url of {"vctm":["invalid-b64url!"]})
    const sdJwtVC = 'eyJ2Y3RtIjpbImludmFsaWQtYjY0dXJsISJdfQ.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.c2lnbmF0dXJl';
    expect(() => extractEmbeddedTypeMetadata(sdJwtVC)).toThrow(
      new SDJWTVCError('Failed to decode base64url vctm entry: invalid-b64url!. Error: Invalid base64url string'),
    );
  });

  it('should correctly decode and return type metadata documents', () => {
    const doc1 = { type: 'doc1', data: 'test1' };
    const doc2 = { type: 'doc2', data: 'test2' };
    const encodedDoc1 = Buffer.from(JSON.stringify(doc1)).toString('base64url');
    const encodedDoc2 = Buffer.from(JSON.stringify(doc2)).toString('base64url');

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
    vct: 'https://betelgeuse.example.com/education_credential',
    name: 'Betelgeuse Education Credential - Preliminary Version',
    description: "This is our development version of the education credential. Don't panic.",
    extends: 'https://galaxy.example.com/galactic-education-credential-0.9',
    'extends#integrity': 'sha256-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-WRL5',
    display: [
      {
        lang: 'en-US',
        name: 'Betelgeuse Education Credential',
        description: 'An education credential for all carbon-based life forms on Betelgeusians',
        rendering: {
          simple: {
            logo: {
              uri: 'https://betelgeuse.example.com/public/education-logo.png',
              'uri#integrity': 'sha256-LmXfh-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1V',
              alt_text: 'Betelgeuse Ministry of Education logo',
            },
            background_color: '#12107c',
            text_color: '#FFFFFF',
          },
          svg_templates: [
            {
              uri: 'https://betelgeuse.example.com/public/credential-english.svg',
              'uri#integrity': 'sha256-8cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-9c',
              properties: {
                orientation: 'landscape',
                color_scheme: 'light',
                contrast: 'high',
              },
            },
          ],
        },
      },
      {
        lang: 'de-DE',
        name: 'Betelgeuse-Bildungsnachweis',
        rendering: {
          simple: {
            logo: {
              uri: 'https://betelgeuse.example.com/public/education-logo-de.png',
              'uri#integrity': 'sha256-LmXfh-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1V',
              alt_text: 'Logo des Betelgeusischen Bildungsministeriums',
            },
            background_color: '#12107c',
            text_color: '#FFFFFF',
          },
          svg_templates: [
            {
              uri: 'https://betelgeuse.example.com/public/credential-german.svg',
              'uri#integrity': 'sha256-8cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-9c',
              properties: {
                orientation: 'landscape',
                color_scheme: 'light',
                contrast: 'high',
              },
            },
          ],
        },
      },
    ],
    claims: [
      {
        path: ['name'],
        display: [
          {
            lang: 'de-DE',
            label: 'Vor- und Nachname',
            description: 'Der Name des Studenten',
          },
          {
            lang: 'en-US',
            label: 'Name',
            description: 'The name of the student',
          },
        ],
        sd: 'allowed',
      },
      {
        path: ['address'],
        display: [
          {
            lang: 'de-DE',
            label: 'Adresse',
            description: 'Adresse zum Zeitpunkt des Abschlusses',
          },
          {
            lang: 'en-US',
            label: 'Address',
            description: 'Address at the time of graduation',
          },
        ],
        sd: 'always',
      },
      {
        path: ['address', 'street_address'],
        display: [
          {
            lang: 'de-DE',
            label: 'Straße',
          },
          {
            lang: 'en-US',
            label: 'Street Address',
          },
        ],
        sd: 'always',
        svg_id: 'address_street_address',
      },
      {
        path: ['degrees', null],
        display: [
          {
            lang: 'de-DE',
            label: 'Abschluss',
            description: 'Der Abschluss des Studenten',
          },
          {
            lang: 'en-US',
            label: 'Degree',
            description: 'Degree earned by the student',
          },
        ],
        sd: 'allowed',
      },
    ],
    schema_uri: 'https://exampleuniversity.com/public/credential-schema-0.9',
    'schema_uri#integrity': 'sha256-o984vn819a48ui1llkwPmKjZ5t0WRL5ca_xGgX3c1VLmXfh',
  };

  const mockHasher: SDJWTHasher = jest.fn();

  beforeEach(() => {
    jest.resetAllMocks();
    (global as any).fetch = jest.fn();

    (mockHasher as jest.Mock).mockImplementation((data: string): string => {
      return crypto.createHash('sha256').update(data).digest('base64url');
    });
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
    const contentHash = mockHasher(rawContent);
    console.log(`Content hash for integrity check: ${contentHash}`);
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': contentHash };

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

  it('should perform integrity check with algorithm prefix in vct#integrity', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const contentHash = mockHasher(rawContent);
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
    const wrongHashClaim = 'sha256-totally-different-hash-value';
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
    const contentHash = mockHasher(rawContent);
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': contentHash };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear();

    const result = await fetchTypeMetadataFromUrl(payload);
    expect(result).toEqual(mockTypeMetadata);
    expect(mockHasher).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should not perform integrity check if vct#integrity is not present, even if hasher is provided', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const payload = { ...mockPayloadBase, vct: vctUrl };

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

  it('should use custom algorithm prefixes when provided', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const contentHash = mockHasher(rawContent);
    const customPrefix = 'blake2b-';
    const integrityClaim = `${customPrefix}${contentHash}`;
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': integrityClaim };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear();

    const result = await fetchTypeMetadataFromUrl(payload, {
      hasher: mockHasher,
      algorithmPrefixes: [customPrefix, 'sha256-', 'sha384-'],
    });

    expect(result).toEqual(mockTypeMetadata);
    expect(mockHasher).toHaveBeenCalledWith(rawContent);
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });

  it('should fallback to default algorithm prefixes when custom prefixes are not provided', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const contentHash = mockHasher(rawContent);
    const integrityClaim = `sha512-${contentHash}`; // using default prefix
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

  it('should not strip prefix if it is not in the configured algorithm prefixes', async () => {
    const vctUrl = 'https://example.com/metadata.json';
    const rawContent = JSON.stringify(mockTypeMetadata);
    const calculatedHash = mockHasher(rawContent);
    const unknownPrefix = 'unknown-';
    const integrityClaimWithUnknownPrefix = `${unknownPrefix}${calculatedHash}`;
    const payload = { ...mockPayloadBase, vct: vctUrl, 'vct#integrity': integrityClaimWithUnknownPrefix };

    (global as any).fetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(rawContent),
    });
    (mockHasher as jest.Mock).mockClear();

    // This should fail because the unknown prefix won't be stripped,
    // so expectedHash will be 'unknown-<hash>' but calculatedHash will be '<hash>'
    await expect(
      fetchTypeMetadataFromUrl(payload, {
        hasher: mockHasher,
        algorithmPrefixes: ['sha256-', 'sha384-', 'sha512-'], // unknown- not included
      }),
    ).rejects.toThrow(SDJWTVCError);

    expect(mockHasher).toHaveBeenCalledWith(rawContent);
    expect(fetch).toHaveBeenCalledWith(vctUrl);
  });
});
