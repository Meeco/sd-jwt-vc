import { generateKeyPair } from 'jose';

import { DisclosureFrame, decodeDisclosures, decodeJWT } from '@meeco/sd-jwt';
import { Issuer } from './issuer';
import { hasherCallbackFn, signerCallbackFn } from './test-utils/helpers';
import {
  CreateSDJWTPayload,
  HasherConfig,
  ReservedJWTClaimKeys,
  SD_JWT_FORMAT_SEPARATOR,
  SignerConfig,
  VCClaims,
} from './types';
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

    const payload: CreateSDJWTPayload = {
      iat: Math.floor(Date.now() / 1000),
      cnf: {
        jwk: holderPublicKey,
      },
      iss: 'https://valid.issuer.url',
      vct: 'https://credentials.example.com/identity_credential',
      status: {
        idx: 0,
        uri: 'https://valid.status.url',
      },
    };

    const vcClaims: VCClaims = {
      person: {
        name: 'test person',
        age: 25,
      },
    };

    const sdVCClaimsDisclosureFrame: DisclosureFrame = { person: { _sd: ['name', 'age'] } };
    const sdVCHeader = {
      kid: '1b94c',
      x5c: [
        'MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB...',
        'MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJC...',
      ],
    };

    const VCSDJwt = await issuer.createVCSDJWT(vcClaims, payload, sdVCClaimsDisclosureFrame, undefined, sdVCHeader);

    expect(VCSDJwt).toBeDefined();
    expect(typeof VCSDJwt).toBe('string');

    const s = VCSDJwt.split(SD_JWT_FORMAT_SEPARATOR);

    const { header, payload: jwtPayload } = decodeJWT(s.shift() || '');

    expect(header.alg).toEqual(signer.alg);
    expect(header.typ).toEqual('vc+sd-jwt');
    expect(header.x5c).toEqual(sdVCHeader.x5c);
    expect(header.kid).toEqual(sdVCHeader.kid);

    expect(jwtPayload.iss).toEqual(payload.iss);
    expect(jwtPayload.iat).toEqual(payload.iat);
    expect(jwtPayload.nbf).toBeUndefined();
    expect(jwtPayload.exp).toBeUndefined();
    expect(jwtPayload.cnf).toEqual(payload.cnf);
    expect(jwtPayload.vct).toEqual(payload.vct);
    expect(jwtPayload.status).toEqual(payload.status);

    // remove empty string
    s.pop();
    const disclosures = decodeDisclosures(s);
    s.forEach((disclosure) => {
      expect(disclosures.map((m) => m.disclosure)).toContainEqual(disclosure);
    });
  });

  describe('Issuer', () => {
    describe('constructor', () => {
      it('should throw an error if signer callback is not provided', () => {
        expect(() => new Issuer({ alg: supportedAlgorithm.ES256, callback: undefined }, undefined)).toThrow(
          'Signer function is required',
        );
      });

      it('should throw an error if signer alg is not provided', () => {
        expect(() => new Issuer({ alg: undefined, callback: () => Promise.resolve('') }, undefined)).toThrow(
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
        ).toThrow('Hasher function is required');
      });

      it('should throw an error if hasher alg is not provided', () => {
        expect(
          () =>
            new Issuer(
              { callback: () => Promise.resolve(''), alg: supportedAlgorithm.ES256 },
              { callback: () => '', alg: undefined },
            ),
        ).toThrow('algo used for Hasher function is required');
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
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: {},
        },
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrow(
        'Issuer iss (issuer) is required and must be a valid URL',
      );
    });

    it('should throw an error if iss is not a valid URL', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: {},
        },
        iss: 'invalid-url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrow(
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

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrow(
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

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload as any)).toThrow(
        'Payload iat (Issued at - seconds since Unix epoch) is required and must be a number',
      );
    });

    it('should throw an error if cnf is missing', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrow(
        'Payload cnf is required and must be a JWK format',
      );
    });

    it('should throw an error if cnf.jwk is missing', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        cnf: {},
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload as any)).toThrow(
        'Payload cnf is required and must be a JWK format',
      );
    });

    it('should throw an error if cnf.jwk is not an object', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: 'invalid-jwk',
        },
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload as any)).toThrow(
        'Payload cnf.jwk must be valid JWK format',
      );
    });

    it('should throw an error if cnf.jwk is missing kty', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: {
            crv: 'P-256',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
          },
        },
        iss: 'https://valid.issuer.url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrow('Payload cnf.jwk must be valid JWK format');
    });

    it('should throw an error if vct is not a valid String', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
          },
        },
        iss: 'https://valid.issuer.url',
        vct: 123,
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrow('vct value MUST be a case-sensitive string');
    });

    it('should throw an error if vct is not a valid url', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
          },
        },
        iss: 'https://valid.issuer.url',
        vct: 'httpinvalid-url',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).toThrow('vct value MUST be a valid URL');
    });

    it('should not throw an error if all properties are valid', () => {
      const sdJWTPayload = {
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
            y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
          },
        },
        iss: 'https://valid.issuer.url',
        vct: 'https://credentials.example.com/identity_credential',
      };

      expect(() => issuer.validateSDJWTPayload(sdJWTPayload)).not.toThrow();
    });
  });

  describe('validateVCClaims', () => {
    it('should throw an error if claims is missing', () => {
      const claims = undefined;

      expect(() => issuer.validateVCClaims(claims as any)).toThrow('Payload claims is required and must be an object');
    });

    it('should throw an error if claims is not an object', () => {
      expect(() => issuer.validateVCClaims('not an object' as any)).toThrow(
        'Payload claims is required and must be an object',
      );
    });

    it('should throw an error if claims contains a reserved JWT payload key', () => {
      const claims = { [ReservedJWTClaimKeys[0]]: 'value' };
      expect(() => issuer.validateVCClaims(claims)).toThrow(
        `Claim contains reserved JWTPayload key: ${ReservedJWTClaimKeys[0]}`,
      );
    });

    it('should not throw an error if all properties are valid', () => {
      const claims = {
        person: {
          name: 'test person',
          age: 25,
        },
      };

      expect(() => issuer.validateVCClaims(claims)).not.toThrow();
    });
  });

  describe('validateSDVCClaimsDisclosureFrame', () => {
    it('should not throw an error if sdVCClaimsDisclosureFrame is not provided', () => {
      const result = issuer.validateSDVCClaimsDisclosureFrame(undefined);
      expect(() => result).not.toThrow();
      expect(result).toBeUndefined();
    });

    it('should not throw an error if sdVCClaimsDisclosureFrame is provided but _sd is not present', () => {
      const frame = {};
      const result = issuer.validateSDVCClaimsDisclosureFrame(frame);
      expect(() => result).not.toThrow();
      expect(result).toBeUndefined();
    });

    it('should not throw an error if sdVCClaimsDisclosureFrame is provided and _sd is an array but contains no reserved JWT payload keys', () => {
      const frame = { _sd: ['key1', 'key2'] };
      const result = issuer.validateSDVCClaimsDisclosureFrame(frame);
      expect(() => result).not.toThrow();
      expect(result).toBeUndefined();
    });

    it('should throw an error if sdVCClaimsDisclosureFrame is provided and _sd is an array that contains a reserved JWT payload key', () => {
      const frame = { _sd: [ReservedJWTClaimKeys[0]] };
      expect(() => issuer.validateSDVCClaimsDisclosureFrame(frame)).toThrow(
        `Disclosure frame contains reserved JWTPayload key: ${ReservedJWTClaimKeys[0]}`,
      );
    });
  });
});
