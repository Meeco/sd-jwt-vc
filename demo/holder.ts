import { JWK, JWTHeaderParameters, KeyBindingVerifier, Signer, base64encode, decodeJWT } from '@meeco/sd-jwt';
import { createHash } from 'crypto';
import { JWTPayload, KeyLike, SignJWT, importJWK, jwtVerify } from 'jose';
import { Holder, SDJWTVCError, SignerConfig, supportedAlgorithm } from '../dev/src';

const signerCallbackFn = function (privateKey: Uint8Array | KeyLike): Signer {
  return async (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    const signedJWT = await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey);
    const signature = signedJWT.split('.').pop() || '';
    return signature;
  };
};

export const hasherFnResolver = (alg: string) => {
  const hasher = (data: string): string => {
    const digest = createHash(alg).update(data).digest();
    return base64encode(digest);
  };
  return Promise.resolve(hasher);
};

const keyBindingVerifierCallbackFn = function (): KeyBindingVerifier {
  return async (kbjwt: string, holderJWK: JWK) => {
    const { header } = decodeJWT(kbjwt);

    if (!Object.values(supportedAlgorithm).includes(header.alg as supportedAlgorithm)) {
      throw new SDJWTVCError('unsupported algorithm');
    }

    const holderKey = await importJWK(holderJWK, header.alg);
    const verifiedKbJWT = await jwtVerify(kbjwt, holderKey);
    return !!verifiedKbJWT;
  };
};

async function main() {
  const _publicJwk = {
    kty: 'EC',
    x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
    y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
    crv: 'P-256',
  };
  const privateKey = {
    kty: 'EC',
    x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
    y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
    crv: 'P-256',
    d: '9Ie2xvzUdQBGCjT9ktsZYGzwG4hOWea-zvCQSQSWJxk',
  };

  const pk = await importJWK(privateKey);

  const signer: SignerConfig = {
    alg: supportedAlgorithm.ES256,
    callback: signerCallbackFn(pk),
  };
  const holder = new Holder(signer, hasherFnResolver);

  const issuedSDJWT =
    'eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3NDgzMjA5MzksImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHA6Ly9pc3N1ZXIudXJsL2p3a3MiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJfc2QiOlsiYnY3ZmZiaWRnV3JnR19YNTlBUjZYZXBOb3I1RjNZeTNxZ01IOUZHbmlaZyJdLCJfc2RfYWxnIjoic2hhMjU2In0.kngQbIsVNEA03Pif5om5fvnt9C2Sz83c-XblGUAWDyseGYqhSu5nwrdhpB1Gc-WaKrtjFMkFVouxQTGjsWApuA~WyJ6bkZLdk5CZnh4dDNlVDJVIiwicGVyc29uIix7Im5hbWUiOiJ0ZXN0IHBlcnNvbiIsImFnZSI6MjV9XQ~';

  const disclosedList = [
    {
      disclosure: 'WyJ6bkZLdk5CZnh4dDNlVDJVIiwicGVyc29uIix7Im5hbWUiOiJ0ZXN0IHBlcnNvbiIsImFnZSI6MjV9XQ',
      key: 'person',
      value: {
        name: 'test person',
        age: 25,
      },
    },
  ];

  const nonceFromVerifier = 'nIdBbNgRqCXBl8YOkfVdg==';

  const { vcSDJWTWithkeyBindingJWT } = await holder.presentVCSDJWT(issuedSDJWT, disclosedList, {
    nonce: nonceFromVerifier,
    audience: 'https://valid.verifier.url',
    keyBindingVerifyCallbackFn: keyBindingVerifierCallbackFn(),
  });

  console.log(vcSDJWTWithkeyBindingJWT);
}

main();
