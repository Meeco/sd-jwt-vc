import { DisclosureFrame, Hasher, Signer, base64encode } from '@meeco/sd-jwt';
import { createHash } from 'crypto';
import { JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, importJWK } from 'jose';
import {
  CreateSDJWTPayload,
  HasherConfig,
  Issuer,
  SignerConfig,
  defaultHashAlgorithm,
  supportedAlgorithm,
} from '../dev/src';

const hasherCallbackFn = function (alg: string = defaultHashAlgorithm): Hasher {
  return (data: string): string => {
    const digest = createHash(alg).update(data).digest();
    return base64encode(digest);
  };
};

function signerCallbackFn(privateKey: Uint8Array | KeyLike): Signer {
  return async (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    const signedJWT = await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey);
    const signature = signedJWT.split('.').pop() || '';
    return signature;
  };
}

async function main() {
  const _issuerPubKey = await importJWK({
    kty: 'EC',
    x: 'MRbP5zJSo9CxUla-ThmzvwUl_3f76bCwrnuQOPK54dQ',
    y: 't1VIetPpyi7rV8ARvaas1VmPmgd6YGo1e-Z5aqedwEU',
    crv: 'P-256',
  });

  const issuerPK = await importJWK({
    kty: 'EC',
    x: 'MRbP5zJSo9CxUla-ThmzvwUl_3f76bCwrnuQOPK54dQ',
    y: 't1VIetPpyi7rV8ARvaas1VmPmgd6YGo1e-Z5aqedwEU',
    crv: 'P-256',
    d: '91a8E7-m8u8NosyFrkNmIMYyx-biM2GFaX9nQzQyDGU',
  });

  const hasher: HasherConfig = {
    alg: 'sha256',
    callback: hasherCallbackFn('sha256'),
  };
  const signer: SignerConfig = {
    alg: supportedAlgorithm.ES256,
    callback: signerCallbackFn(issuerPK),
  };

  const issuer = new Issuer(signer, hasher);

  const holderPublicKey = {
    kty: 'EC',
    x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
    y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
    crv: 'P-256',
  };

  const payload: CreateSDJWTPayload = {
    iat: Date.now(),
    cnf: {
      jwk: holderPublicKey,
    },
    iss: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    vct: 'https://credentials.example.com/identity_credential',
  };

  const vcClaims = {
    given_name: 'John',
    family_name: 'Doe',
    email: 'johndoe@example.com',
    phone_number: '+1-202-555-0101',
    address: {
      street_address: '123 Main St',
      locality: 'Anytown',
      region: 'Anystate',
      country: 'US',
    },
    birthdate: '1940-01-01',
    is_over_18: true,
    is_over_21: true,
    is_over_65: true,
  };

  const sdVCClaimsDisclosureFrame: DisclosureFrame = {
    _sd: Object.keys(vcClaims),
  };

  const result = await issuer.createVCSDJWT(vcClaims, payload, sdVCClaimsDisclosureFrame);
  console.log(result);
}

main();
