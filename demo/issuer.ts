import { DisclosureFrame, Hasher, Signer, base64encode } from '@meeco/sd-jwt';
import { createHash } from 'crypto';
import { JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, exportJWK, generateKeyPair } from 'jose';
import {
  CreateSDJWTPayload,
  HasherConfig,
  Issuer,
  SignerConfig,
  VCClaimsWithVCDataModel,
  defaultHashAlgorithm,
  supportedAlgorithm,
} from '../dev/src';

const hasherCallbackFn = function (alg: string = defaultHashAlgorithm): Hasher {
  return (data: string): string => {
    const digest = createHash(alg).update(data).digest();
    return base64encode(digest);
  };
};

const signerCallbackFn = function (privateKey: Uint8Array | KeyLike): Signer {
  return (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    return new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey);
  };
};

async function main() {
  const keyPair = await generateKeyPair(supportedAlgorithm.EdDSA);

  const hasher: HasherConfig = {
    alg: 'sha256',
    callback: hasherCallbackFn('sha-256'),
  };
  const signer: SignerConfig = {
    alg: supportedAlgorithm.EdDSA,
    callback: signerCallbackFn(keyPair.privateKey),
  };

  const issuer = new Issuer(signer, hasher);

  const holderPublicKey = await exportJWK(keyPair.publicKey);

  const payload: CreateSDJWTPayload = {
    iat: Date.now(),
    cnf: {
      jwk: holderPublicKey,
    },
    iss: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  };

  const vcClaims: VCClaimsWithVCDataModel = {
    vc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: '9bcc9aaa-3bdc-4414-9450-739c295c752c',
      type: 'StudentID',
      issuer: 'did:ebsi:zvHWX359A3CvfJnCYaAiAde',
      validFrom: '2023-01-01T00:00:00Z',
      validUntil: '2033-01-01T00:00:00Z',
      credentialSubject: {
        id: 'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsDbVZXdb3jzCagESyY4EE2x7Yjx3gNwctoEuRCKKDrdNP3HPFtG8RTvBiYStT5ghBHhHizH2Dy6xQtW3Pd2SecizL9b2jzDCMr7Ka5cRAWZFwvqwAtwTT7xet769y9ERh6',
        familyName: 'Carroll',
        givenName: 'Lewis',
        birthDate: '1832-01-27',
        student: true,
      },
      credentialSchema: {
        id: 'https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/0x23039e6356ea6b703ce672e7cfac0b42765b150f63df78e2bd18ae785787f6a2',
        type: 'FullJsonSchemaValidator2021',
      },
    },
  };

  const sdVCClaimsDisclosureFrame: DisclosureFrame = {
    vc: { credentialSubject: { _sd: ['familyName', 'givenName', 'birthDate', 'student'] } },
  };

  const result = await issuer.createVCSDJWT(vcClaims, payload, sdVCClaimsDisclosureFrame);
  console.log(result);
}

main();
