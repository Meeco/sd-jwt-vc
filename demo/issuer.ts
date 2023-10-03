import { DisclosureFrame, Hasher, SDJWTPayload, Signer, base64encode } from '@meeco/sd-jwt';
import { createHash } from 'crypto';
import { JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, exportJWK, generateKeyPair } from 'jose';
import { HasherConfig, Issuer, SignerConfig, VCClaims, defaultHashAlgorithm, supportedAlgorithm } from '../dev/src';

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
    callback: hasherCallbackFn('sha256'),
  };
  const signer: SignerConfig = {
    alg: supportedAlgorithm.EdDSA,
    callback: signerCallbackFn(keyPair.privateKey),
  };

  const issuer = new Issuer(signer, hasher);

  const holderPublicKey = await exportJWK(keyPair.publicKey);

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

  const result = await issuer.createVCSDJWT(vcClaims, payload, sdVCClaimsDisclosureFrame);
  console.log(result);
}

main();
