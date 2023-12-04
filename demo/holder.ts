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
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MDE3MzE2NTM4NDUsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHA6Ly9pc3N1ZXIudXJsL2p3a3MiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJfc2QiOlsiN29JR0VBWWZ1R0dXTzdrMmhZbHhEQVlOTF9OdHZiVWhjRFd1dF9yNjVMcyIsIkpuNTl2SFBoVVFoRkNVUGh2d3R4cTNVTjhOb2NMXzdDaDJZeWhHVzFuU3MiLCJTa09FXzVzQktzTG9GMnRMbWhvcmo4cm1yeUlNc1FhTTJVai1VcW55YzFzIiwiVUFzc0l6S1RGMFZnUTFLM3ZLWVpOVm9uR29RTDJ6cmR3eDN0V25taUpnZyIsImNmZXd6dGZJeFBYX0hlRzNtRzBDTUs4TDJWSVVDcGZlSGRtSzhnMzJnNVkiLCJlNDRkVUdFZUJqY2xodEN0QnJBbUM4czVuMENBWnNOUm85dk5LTUdMdmhJIiwiaEE5VGg5elhZdVFwMF9IYTdqb09NbVRpVHhVcjdLdnNnSU5zb0pPT09IOCIsIm5xMDE3UWJnYk9HcWptSktMOU1tT1F2aWxFbHRNOGFEUHNZQnVMbkZDc1kiLCJvbUk2S2ZyckpzbDhhQnZWODV0T0lIQWQzcXpxM2pQbWlqVlp3RXVBRkI0Il0sIl9zZF9hbGciOiJzaGEyNTYifQ.ioLFasOlNizRDImDxxP1rvOLX0cf9010up2zhzA6EqTRhc5Cpy9qxCWPu5G1tOWicNqysPqi88ATqD4HRD_zRg~WyJTa0MwMXpMZXZnbDEwakpYIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJRbmZJVE9GUDdrcjhQcUpWIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJudXpYZzRMZEhDRWQyMlRMIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJQb2RwWmF3Q3ZUbW03TGNSIiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0~WyJwZVhLajk0TU5DaEc3TkZLIiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0~WyJERTdPdThRNE54aXI3ZmRnIiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJnQTdUWUJyWnR3VjZMZFlFIiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJ3bFdOSVBmREcxWHNCSW13IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyJWNTY5S2ZzYUFCamFaU0tVIiwiaXNfb3Zlcl82NSIsdHJ1ZV0~';

  const disclosedList = [
    {
      disclosure:
        'WyJwZVhLajk0TU5DaEc3TkZLIiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0',
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
    audience: 'https://valid.verifier.url',
    keyBindingVerifyCallbackFn: keyBindingVerifierCallbackFn(),
  });

  console.log(vcSDJWTWithkeyBindingJWT);
}

main();
