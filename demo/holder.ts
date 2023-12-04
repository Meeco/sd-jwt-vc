import { KeyBindingVerifier, Signer, decodeJWT } from '@meeco/sd-jwt';
import { JWK, JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, importJWK, jwtVerify } from 'jose';
import { Holder, SDJWTVCError, SignerConfig, supportedAlgorithm } from '../dev/src';

const signerCallbackFn = function (privateKey: Uint8Array | KeyLike): Signer {
  return async (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    const signedJWT = await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey);
    const signature = signedJWT.split('.').pop() || '';
    return signature;
  };
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
  const holder = new Holder(signer);

  const issuedSDJWT =
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MDE2NjY1NTMxNTAsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6ImRpZDprZXk6ejZNa2hhWGdCWkR2b3REa0w1MjU3ZmFpenRpR2lDMlF0S0xHcGJubkVHdGEyZG9LIiwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwiX3NkIjpbIjh4UDRZSXJVWGh3Z29DVmN0dElkcW5PUWxrWEZsaGVyZ0tzWnQxLVQ4MlkiLCJJeS03WkJrUGN1OW90V05OYW9yS0V3V3pwUWtpVzBhV3luTFRjWmN5R3E4IiwiT3dFU1N1N0d3d3k0WlJZVXo1YkNzYkVKbGcwSGZka09yN21MRUYwMjVqRSIsIlJRcGRGTk9qVGQxR2dtVGZDQXh4VE1LdDVQajRUeUpOWFhBeFJ2WHZtYVkiLCJSeDMzNkI1MUxiVVJjcHh3dU1DZEJqQjFZdTNQSlRWeU1XRGVEZzY2NTlBIiwiV3AzZ2JRRVZDU1NtWUJZcm4tM3B2QUdkd1lJeHJzYVJtbUc1TmREUDZBUSIsImRrRUhiSHllRlRTWmtpU2hqYlk2amVUQWt0SllXLWNLNTl0Y2IxbmNlV1UiLCJzc0RzSTZQMllva1lpTGhNNXhBVWliWUQ2OThVVVVHVEFrVlUzZ00zM0pVIiwieFNCeDN2Q2ttMEVIY3dEUnczYWM3NUVISy1maTQwU0FSdTZiaTZUU19fZyJdLCJfc2RfYWxnIjoic2hhMjU2In0.qEutt-rPDRUTuOXm0nn1X-qYmUSnd7E2daJj_FojOoVTfK6SGSXzVpXnHGu_AOIMPS4p5HuULlU3uNBNgZwr7A~WyIxVHJEOXR4YUI1Tnc3alZqIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJjc2RlQUl0UjhiVjBadTJmIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI5NEw1eUJVVHhwcTlvcXp2IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJDNkk0ZXFoYkd5NnNrV2s5IiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0~WyJWREVwdUg0bkNwNGNodXY2IiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0~WyJsT3FjNkpuSkxPa2habnBmIiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJNOEhkcUNNaUFBRm11aUJiIiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJjY05NUzhIVGZXZWI0SDdtIiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyIzNkU3MXBobFlkMEJWdThkIiwiaXNfb3Zlcl82NSIsdHJ1ZV0~';

  const disclosedList = [
    {
      disclosure:
        'WyJWREVwdUg0bkNwNGNodXY2IiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0',
      key: 'address',
      value: {
        street_address: '123 Main St',
        locality: 'Anytown',
        region: 'Anystate',
        country: 'US',
      },
    },
  ];

  const nonceFromVerifier = 'nIdBbNgRqCXBl8YOkfVdg==';

  const { vcSDJWTWithkeyBindingJWT } = await holder.presentVCSDJWT(issuedSDJWT, disclosedList, {
    nonce: nonceFromVerifier,
    audience: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    keyBindingVerifyCallbackFn: keyBindingVerifierCallbackFn(),
  });

  console.log(vcSDJWTWithkeyBindingJWT);
}

main();
