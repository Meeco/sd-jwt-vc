import { generateKeyPair } from 'jose';

import { DisclosureFrame, SDJWTPayload, decodeDisclosure, decodeJWT } from '@meeco/sd-jwt';
import { Issuer } from './issuer';
import { hasherCallbackFn, signerCallbackFn } from './test-utils/helpers';
import { HasherConfig, SD_JWT_FORMAT_SEPARATOR, SignerConfig, VCClaims } from './types';
import { supportedAlgorithm } from './util';

describe('Issuer', () => {
  let issuer: Issuer;
  let hasher: HasherConfig;
  let signer: SignerConfig;

  beforeEach(async () => {
    const keyPair = await generateKeyPair(supportedAlgorithm.EdDSA);

    signer = {
      alg: supportedAlgorithm.EdDSA,
      callback: signerCallbackFn(keyPair.privateKey),
    };
    hasher = {
      alg: 'sha256',
      callback: hasherCallbackFn('sha256'),
    };

    issuer = new Issuer(signer, hasher);
  });

  it('should create a verifiable credential SD JWT', async () => {
    const holderPublicKey = {
      kty: 'EC',
      x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
      y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
      crv: 'P-256',
    };

    const payload: SDJWTPayload = {
      iat: Date.now(),
      cnf: {
        jwk: holderPublicKey,
      },
      iss: 'https://valid.issuer.url',
    };

    const vcClaims: VCClaims = {
      type: 'VerifiableCredential',
      status: {
        idx: 'statusIndex',
        uri: 'https://valid.status.url',
      },
      person: {
        name: 'test person',
        age: 25,
      },
    };

    const sdVCClaimsDisclosureFrame: DisclosureFrame = { person: { _sd: ['name', 'age'] } };

    const VCSDJwt = await issuer.createVCSDJWT(vcClaims, payload, sdVCClaimsDisclosureFrame);

    expect(VCSDJwt).toBeDefined();
    expect(typeof VCSDJwt).toBe('string');

    const s = VCSDJwt.split(SD_JWT_FORMAT_SEPARATOR);

    const { header, payload: jwtPayload } = decodeJWT(s.shift() || '');

    expect(header.alg).toEqual(signer.alg);
    expect(header.typ).toEqual('vc+sd-jwt');

    expect(jwtPayload.iss).toEqual(payload.iss);
    expect(jwtPayload.iat).toEqual(payload.iat);
    expect(jwtPayload.nbf).toBeUndefined();
    expect(jwtPayload.exp).toBeUndefined();
    expect(jwtPayload.cnf).toEqual(payload.cnf);

    // remove empty string
    s.pop();
    const disclosures = decodeDisclosure(s);
    s.forEach((disclosure) => {
      expect(disclosures.map((m) => m.disclosure)).toContainEqual(disclosure);
    });
  });

  describe('Issuer', () => {
    describe('constructor', () => {
      it('should throw an error if signer callback is not provided', () => {
        expect(() => new Issuer({ alg: supportedAlgorithm.ES256, callback: undefined }, undefined)).toThrowError(
          'Signer function is required',
        );
      });

      it('should throw an error if signer alg is not provided', () => {
        expect(() => new Issuer({ alg: undefined, callback: () => Promise.resolve('') }, undefined)).toThrowError(
          'algo used for Signer function is required',
        );
      });

      it('should throw an error if hasher callback is not provided', () => {
        expect(
          () =>
            new Issuer(
              { callback: () => Promise.resolve(''), alg: supportedAlgorithm.ES256 },
              { alg: 'SHA256', callback: undefined },
            ),
        ).toThrowError('Hasher function is required');
      });

      it('should throw an error if hasher alg is not provided', () => {
        expect(
          () =>
            new Issuer(
              { callback: () => Promise.resolve(''), alg: supportedAlgorithm.ES256 },
              { callback: () => '', alg: undefined },
            ),
        ).toThrowError('algo used for Hasher function is required');
      });

      it('should create an instance of Issuer if all required parameters are provided', () => {
        const signer = { callback: () => Promise.resolve(''), alg: supportedAlgorithm.ES256 };
        const hasher = { callback: () => '', alg: 'SHA256' };
        const issuer = new Issuer(signer, hasher);
        expect(issuer).toBeInstanceOf(Issuer);
        expect(issuer.getSigner).toEqual(signer);
        expect(issuer.getHasher).toEqual(hasher);
      });
    });
  });

  describe('validateSDJWTPayload', () => {
    it('should throw an error if iss is missing', () => {
      const sdJWTPayload = {
        iat: Date.now(),
        cnf: {
          jwk: {},
        },
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrowError(
        'Issuer iss (issuer) is required and must be a valid URL',
      );
    });

    it('should throw an error if iss is not a valid URL', () => {
      const sdJWTPayload = {
        iat: Date.now(),
        cnf: {
          jwk: {},
        },
        iss: 'invalid-url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrowError(
        'Issuer iss (issuer) is required and must be a valid URL',
      );
    });

    it('should throw an error if iat is missing', () => {
      const sdJWTPayload = {
        cnf: {
          jwk: {},
        },
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrowError(
        'Payload iat (Issued at - seconds since Unix epoch) is required and must be a number',
      );
    });

    it('should throw an error if iat is not a number', () => {
      const sdJWTPayload = {
        iat: 'invalid-iat',
        cnf: {
          jwk: {},
        },
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload as any)).toThrowError(
        'Payload iat (Issued at - seconds since Unix epoch) is required and must be a number',
      );
    });

    it('should throw an error if cnf is missing', () => {
      const sdJWTPayload = {
        iat: Date.now(),
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrowError(
        'Payload cnf is required and must be a JWK format',
      );
    });

    it('should throw an error if cnf.jwk is missing', () => {
      const sdJWTPayload = {
        iat: Date.now(),
        cnf: {},
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload as any)).toThrowError(
        'Payload cnf is required and must be a JWK format',
      );
    });

    it('should throw an error if cnf.jwk is not an object', () => {
      const sdJWTPayload = {
        iat: Date.now(),
        cnf: {
          jwk: 'invalid-jwk',
        },
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload as any)).toThrowError(
        'Payload cnf.jwk must be valid JWK format',
      );
    });

    it('should throw an error if cnf.jwk is missing kty', () => {
      const sdJWTPayload = {
        iat: Date.now(),
        cnf: {
          jwk: {
            crv: 'P-256',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
          },
        },
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrowError('Payload cnf.jwk must be valid JWK format');
    });

    it('should not throw an error if all properties are valid', () => {
      const sdJWTPayload = {
        iat: Date.now(),
        cnf: {
          jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
          },
        },
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).not.toThrow();
    });
  });

  describe('validateVCClaims', () => {
    it('should throw an error if claims is missing', () => {
      const claims = undefined;

      expect(() => issuer.validateVCClaims(claims as any)).toThrowError(
        'Payload claims is required and must be an object',
      );
    });

    it('should throw an error if type is missing', () => {
      const claims = {
        status: {
          idx: 'statusIndex',
          uri: 'https://valid.status.url',
        },
      };

      expect(() => issuer.validateVCClaims(claims as any)).toThrowError(
        'Payload type is required and must be a string',
      );
    });

    it('should throw an error if type is not a string', () => {
      const claims = {
        type: {},
        status: {
          idx: 'statusIndex',
          uri: 'https://valid.status.url',
        },
      };

      expect(() => issuer.validateVCClaims(claims as any)).toThrowError(
        'Payload type is required and must be a string',
      );
    });

    it('should throw an error if status is not an object', () => {
      const claims = {
        type: 'VerifiableCredential',
        status: 'invalid-status',
      };

      expect(() => issuer.validateVCClaims(claims as any)).toThrowError(
        'Payload status must be an object with idx and uri properties',
      );
    });

    it('should throw an error if status.idx is missing', () => {
      const claims = {
        type: 'VerifiableCredential',
        status: {
          uri: 'https://valid.status.url',
        },
      };

      expect(() => issuer.validateVCClaims(claims as any)).toThrowError(
        'Payload status must be an object with idx and uri properties',
      );
    });

    it('should throw an error if status.uri is missing', () => {
      const claims = {
        type: 'VerifiableCredential',
        status: {
          idx: 'statusIndex',
        },
      };

      expect(() => issuer.validateVCClaims(claims as any)).toThrowError(
        'Payload status must be an object with idx and uri properties',
      );
    });

    it('should not throw an error if all properties are valid', () => {
      const claims = {
        type: 'VerifiableCredential',
        status: {
          idx: 'statusIndex',
          uri: 'https://valid.status.url',
        },
      };

      expect(() => issuer.validateVCClaims(claims)).not.toThrow();
    });
  });
});
