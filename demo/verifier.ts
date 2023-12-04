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
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MDE3MzE2NTM4NDUsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHA6Ly9pc3N1ZXIudXJsL2p3a3MiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJfc2QiOlsiN29JR0VBWWZ1R0dXTzdrMmhZbHhEQVlOTF9OdHZiVWhjRFd1dF9yNjVMcyIsIkpuNTl2SFBoVVFoRkNVUGh2d3R4cTNVTjhOb2NMXzdDaDJZeWhHVzFuU3MiLCJTa09FXzVzQktzTG9GMnRMbWhvcmo4cm1yeUlNc1FhTTJVai1VcW55YzFzIiwiVUFzc0l6S1RGMFZnUTFLM3ZLWVpOVm9uR29RTDJ6cmR3eDN0V25taUpnZyIsImNmZXd6dGZJeFBYX0hlRzNtRzBDTUs4TDJWSVVDcGZlSGRtSzhnMzJnNVkiLCJlNDRkVUdFZUJqY2xodEN0QnJBbUM4czVuMENBWnNOUm85dk5LTUdMdmhJIiwiaEE5VGg5elhZdVFwMF9IYTdqb09NbVRpVHhVcjdLdnNnSU5zb0pPT09IOCIsIm5xMDE3UWJnYk9HcWptSktMOU1tT1F2aWxFbHRNOGFEUHNZQnVMbkZDc1kiLCJvbUk2S2ZyckpzbDhhQnZWODV0T0lIQWQzcXpxM2pQbWlqVlp3RXVBRkI0Il0sIl9zZF9hbGciOiJzaGEyNTYifQ.ioLFasOlNizRDImDxxP1rvOLX0cf9010up2zhzA6EqTRhc5Cpy9qxCWPu5G1tOWicNqysPqi88ATqD4HRD_zRg~WyJwZVhLajk0TU5DaEc3TkZLIiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0~';
  const kbJWT =
    'eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZ1JxQ1hCbDhZT2tmVmRnPT0iLCJpYXQiOjE3MDE3MzE4MjQ3Nzl9.27pQYld_NI5dcmAz4m2a_vKnQ_SYCkYxykmKTmYvH1Qg2xUt3G9tCTsX68tU3kFS6_m9VlgdBdSSsOaoX1ALKA';

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
    kbVeriferCallbackFn('https://valid.verifier.url', nonce),
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
