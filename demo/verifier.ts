import { Hasher, KeyBindingVerifier, base64encode, decodeJWT } from '@meeco/sd-jwt';
import { createHash } from 'crypto';
import { JWK, KeyLike, importJWK, jwtVerify } from 'jose';
import { Verifier, defaultHashAlgorithm, supportedAlgorithm } from '../dev/src';

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
        throw new Error('aud mismatch');
      }
      if (payload.nonce !== expectedNonce) {
        throw new Error('nonce mismatch');
      }
    }

    if (!Object.values(supportedAlgorithm).includes(header.alg as supportedAlgorithm)) {
      throw new Error('unsupported algorithm');
    }

    const holderKey = await importJWK(holderJWK, header.alg);
    const verifiedKbJWT = await jwtVerify(kbjwt, holderKey);
    return !!verifiedKbJWT;
  };
}

async function main() {
  const verifier = new Verifier();
  const { vcSDJWTWithkeyBindingJWT, nonce } = {
    vcSDJWTWithkeyBindingJWT:
      'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZWdScUNYQmw4WU9rZlZkZz09IiwiaWF0IjoxNjk1NzgzOTgzMDQxfQ.YwgHkYEpCFRHny5L4KdnU_qARVHL2jAScodRqfF5UP50nbryqIl4i1OuaxuQKala_uYNT-e0D4xzghoxWE56SQ',
    nonce: 'nIdBbNegRqCXBl8YOkfVdg==',
  };

  const issuerPubKey = await importJWK({
    crv: 'Ed25519',
    x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
    kty: 'OKP',
  });

  const result = await verifier.verifyVerifiableCredentialSDJWT(
    vcSDJWTWithkeyBindingJWT,
    verifierCallbackFn(issuerPubKey),
    hasherCallbackFn(defaultHashAlgorithm),
    kbVeriferCallbackFn('https://valid.verifier.url', nonce),
  );
  console.log(result);
}

main();
