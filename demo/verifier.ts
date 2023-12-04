import { Hasher, KeyBindingVerifier, base64encode, decodeJWT } from '@meeco/sd-jwt';
import { createHash } from 'crypto';
import { JWK, KeyLike, importJWK, jwtVerify } from 'jose';
import { SDJWTVCError, Verifier, defaultHashAlgorithm, supportedAlgorithm } from '../dev/src';

function verifierCallbackFn(publicKey: Uint8Array | KeyLike) {
  return async (jwt: string): Promise<boolean> => {
    const verifiedKbJWT = await jwtVerify(jwt, publicKey);
    return !!verifiedKbJWT;
  };
}

function hasherCallbackFn(alg: string = defaultHashAlgorithm): Hasher {
  return (data: string): string => {
    const digest = createHash(alg).update(data).digest();
    return base64encode(digest);
  };
}

function kbVeriferCallbackFn(expectedAud: string, expectedNonce: string): KeyBindingVerifier {
  return async (kbjwt: string, holderJWK: JWK) => {
    const { header, payload } = decodeJWT(kbjwt);

    if (expectedAud || expectedNonce) {
      if (payload.aud !== expectedAud) {
        throw new SDJWTVCError('aud mismatch');
      }
      if (payload.nonce !== expectedNonce) {
        throw new SDJWTVCError('nonce mismatch');
      }
    }

    if (!Object.values(supportedAlgorithm).includes(header.alg as supportedAlgorithm)) {
      throw new SDJWTVCError('unsupported algorithm');
    }

    const holderKey = await importJWK(holderJWK, header.alg);
    const verifiedKbJWT = await jwtVerify(kbjwt, holderKey);
    console.log('verifiedKbJWT', verifiedKbJWT);
    return !!verifiedKbJWT;
  };
}

async function main() {
  const verifier = new Verifier();

  const vcSDJWTWithoutkeyBindingJWT =
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MDE2NjY1NTMxNTAsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6ImRpZDprZXk6ejZNa2hhWGdCWkR2b3REa0w1MjU3ZmFpenRpR2lDMlF0S0xHcGJubkVHdGEyZG9LIiwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwiX3NkIjpbIjh4UDRZSXJVWGh3Z29DVmN0dElkcW5PUWxrWEZsaGVyZ0tzWnQxLVQ4MlkiLCJJeS03WkJrUGN1OW90V05OYW9yS0V3V3pwUWtpVzBhV3luTFRjWmN5R3E4IiwiT3dFU1N1N0d3d3k0WlJZVXo1YkNzYkVKbGcwSGZka09yN21MRUYwMjVqRSIsIlJRcGRGTk9qVGQxR2dtVGZDQXh4VE1LdDVQajRUeUpOWFhBeFJ2WHZtYVkiLCJSeDMzNkI1MUxiVVJjcHh3dU1DZEJqQjFZdTNQSlRWeU1XRGVEZzY2NTlBIiwiV3AzZ2JRRVZDU1NtWUJZcm4tM3B2QUdkd1lJeHJzYVJtbUc1TmREUDZBUSIsImRrRUhiSHllRlRTWmtpU2hqYlk2amVUQWt0SllXLWNLNTl0Y2IxbmNlV1UiLCJzc0RzSTZQMllva1lpTGhNNXhBVWliWUQ2OThVVVVHVEFrVlUzZ00zM0pVIiwieFNCeDN2Q2ttMEVIY3dEUnczYWM3NUVISy1maTQwU0FSdTZiaTZUU19fZyJdLCJfc2RfYWxnIjoic2hhMjU2In0.qEutt-rPDRUTuOXm0nn1X-qYmUSnd7E2daJj_FojOoVTfK6SGSXzVpXnHGu_AOIMPS4p5HuULlU3uNBNgZwr7A~WyJWREVwdUg0bkNwNGNodXY2IiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0~';
  const kbJWT =
    'eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJkaWQ6a2V5Ono2TWtoYVhnQlpEdm90RGtMNTI1N2ZhaXp0aUdpQzJRdEtMR3Bibm5FR3RhMmRvSyIsIm5vbmNlIjoibklkQmJOZ1JxQ1hCbDhZT2tmVmRnPT0iLCJpYXQiOjE3MDE2NjY2MjE1OTd9.mjJEnjxuLvRHR6E_NWUCAIJzqpduSZxAwc50DcC3WSkZlEMtiOH_dxYO-VUXRjxE4_XuJNbxvLCXzTI8g4lYgA';

  const nonce = 'nIdBbNgRqCXBl8YOkfVdg==';
  const issuerPubKey = await importJWK({
    kty: 'EC',
    x: 'MRbP5zJSo9CxUla-ThmzvwUl_3f76bCwrnuQOPK54dQ',
    y: 't1VIetPpyi7rV8ARvaas1VmPmgd6YGo1e-Z5aqedwEU',
    crv: 'P-256',
  });

  const verifywithkbjwt = await verifier.verifyVCSDJWT(
    vcSDJWTWithoutkeyBindingJWT + kbJWT,
    verifierCallbackFn(issuerPubKey),
    hasherCallbackFn(defaultHashAlgorithm),
    kbVeriferCallbackFn('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', nonce),
  );
  console.log('verifywithkbjwt');
  console.log(verifywithkbjwt);

  const verifywithoutkbjwt = await verifier.verifyVCSDJWT(
    vcSDJWTWithoutkeyBindingJWT,
    verifierCallbackFn(issuerPubKey),
    hasherCallbackFn(defaultHashAlgorithm),
  );
  console.log('verifywithoutkbjwt');
  console.log(verifywithoutkbjwt);
}

main();
