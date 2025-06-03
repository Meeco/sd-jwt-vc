[![npm](https://img.shields.io/npm/dt/@meeco/sd-jwt-vc.svg)](https://www.npmjs.com/package/@meeco/sd-jwt-vc)
[![npm](https://img.shields.io/npm/v/@meeco/sd-jwt-vc.svg)](https://www.npmjs.com/package/@meeco/sd-jwt-vc)

# SD-JWT-VC

This is an implementation of [SD-JWT VC (I-D version 08)](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html) in Typescript. It provides a higher-level interface on top of the [@meeco/sd-jwt](https://github.com/Meeco/sd-jwt) library to create the compliant SD-JWT VCs.

**Note on `typ` header (as of v2.0.0):**

- The `typ` header for issued SD-JWT VCs is `dc+sd-jwt`.
- The `Verifier` will accept both `vc+sd-jwt` and `dc+sd-jwt`.

## Installation

```bash
npm install @meeco/sd-jwt-vc
```

## Usage

The library exposes three classes

### Issuer

This is a TypeScript class that represents an issuer of Verifiable Credentials (VCs) that can create Signed and Disclosed JWTs (SD JWTs) for VCs.

#### Usage

To use the Issuer class, you need to create an instance of it by passing in a signer configuration object and a hasher configuration object.
signer configuration callback function will be used to sign the SD JWTs and hasher configuration callback function will be used to hash the disclosued claims in the SD JWTs.

Here's an example:

```typescript
import { createHash } from 'crypto';
import { JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, exportJWK, generateKeyPair } from 'jose';
import { DisclosureFrame, Hasher, SDJWTPayload, Signer, base64encode } from '@meeco/sd-jwt';
import {
  CreateSDJWTPayload,
  HasherConfig,
  Issuer,
  SignerConfig,
  VCClaims,
  defaultHashAlgorithm,
  supportedAlgorithm,
} from '@meeco/sd-jwt-vc';

const hasherCallbackFn = function (alg: string = defaultHashAlgorithm): Hasher {
  return (data: string): string => {
    const digest = createHash(alg).update(data).digest();
    return base64encode(digest);
  };
};

const signerCallbackFn = function (privateKey: Uint8Array | KeyLike): Signer {
  return (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    return (await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey)).split('.').pop();
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
}

main();
```

- singner: The signer configuration object. It contains the following properties:
  - alg: The algorithm to use for signing the SD JWTs. Must be one of the supported algorithms ('EdDSA', 'ES256', 'ES256K', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512').
  - callback: The callback function that will be used to sign the SD JWTs. It must be a function that takes a string and returns a string.
- hasher: The hasher configuration object. It contains the following properties:
  - alg: The algorithm to use for hashing the SD JWTs. Must be one of the available algorithms supported by OpenSSL.
  - callback: The callback function that will be used to hash the SD JWTs. It must be a function that takes a string and returns a string.

#### createVCSDJWT

Once you have an instance of the Issuer class, you can use it to create SD JWTs for VCs. Here's an example:

```typescript
async function main() {
 ...
 ...

  const holderPublicKey = await exportJWK(keyPair.publicKey);

  const payload: CreateSDJWTPayload = {
    iat: Math.floor(Date.now() / 1000),
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
```

This will create an SD JWT for the given VC claims and SD JWT payload for given [disclosure frame](https://github.com/Meeco/sd-jwt#packsdjwt-examples).

### Holder

This is a TypeScript class that represents a holder of Verifiable Credentials (VCs) that can verify Signed and Present SD JWT VC's with Key Binding to Verifier.

#### Usage

To use the Holder class, you need to create an instance of it by passing in a Holder Signer configuration object and Hasher function resolver. Here's an example:

```typescript
import { KeyBindingVerifier, Signer, decodeJWT, base64encode } from '@meeco/sd-jwt';
import { JWK, JWTHeaderParameters, JWTPayload, KeyLike, SignJWT, importJWK, jwtVerify } from 'jose';
import { Holder, SignerConfig, supportedAlgorithm } from '@meeco/sd-jwt-vc';
import { createHash } from 'crypto';

const hasherFnResolver = (alg: string) => {
  const hasher = (data: string): string => {
    const digest = createHash(alg).update(data).digest();
    return base64encode(digest);
  };

  return Promise.resolve(hasher);
};

const signerCallbackFn = function (privateKey: Uint8Array | KeyLike): Signer {
  return (protectedHeader: JWTHeaderParameters, payload: JWTPayload): Promise<string> => {
    return (await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(privateKey)).split('.').pop();
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
}

main();
```

#### presentVCSDJWT

Once you have an instance of the Holder class, you can use it to present SD JWTs for VCs. Here's an example:

```typescript

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
 ...
 ...

  const issuedSDJWT =
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~';

  const disclosureList = [
    {
      key: 'name',
      value: 'test person',
      disclosure: 'WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0',
    },
  ];

  const nonceFromVerifier = 'nIdBbNgRqCXBl8YOkfVdg==';

  const { vcSDJWTWithkeyBindingJWT } = await holder.presentVCSDJWT(issuedSDJWT, disclosureList, {
    nonce: nonceFromVerifier,
    audience: 'https://valid.verifier.url',
    keyBindingVerifyCallbackFn: keyBindingVerifierCallbackFn(),
  });

  console.log(vcSDJWTWithkeyBindingJWT);
}

main();
```

This will create an SD JWT VC with Key Binding JWT. The holder can then send this JWT to the verifier.

### Verifier

This is a TypeScript class that represents a verifier of Verifiable Credentials (VCs) that can verify Signed and Disclosed SD JWT VC's with Key Binding to Holder.

#### Usage

To use the Verifier class, you need to create an instance of it and call the verifyVCSDJWT method on it.
verifyVCSDJWT method takes the following parameters:

- vcSDJWTWithkeyBindingJWT: The SD JWT VC with Key Binding JWT that was sent by the holder.
- verifierCallbackFn: The callback function that will be used to verify the SD JWT VC with Key Binding JWT. It must be a function that takes a string and returns a boolean.
- hasherCallbackFn: The callback function that will be used to hash the disclosued claims in the SD JWTs. It must be a function that takes a string and returns a string.
- kbVeriferCallbackFn: The callback function that will be used to verify the key binding in the SD JWT VC with Key Binding JWT. It must be a function that takes a string and returns a boolean.

Here's an example:

```typescript
import { Hasher, KeyBindingVerifier, base64encode, decodeJWT } from '@meeco/sd-jwt';
import { createHash } from 'crypto';
import { JWK, KeyLike, importJWK, jwtVerify } from 'jose';
import { Verifier, defaultHashAlgorithm, supportedAlgorithm } from '@meeco/sd-jwt-vc';

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

function kbVeriferCallbackFn(expectedAud: string, expectedNonce: string, expectedSdHash: string): KeyBindingVerifier {
  return async (kbjwt: string, holderJWK: JWK) => {
    const { header, payload } = decodeJWT(kbjwt);

    if (expectedAud || expectedNonce || expectedSdHash) {
      if (payload.aud !== expectedAud) {
        throw new SDJWTVCError('aud mismatch');
      }
      if (payload.nonce !== expectedNonce) {
        throw new SDJWTVCError('nonce mismatch');
      }
      if (payload.sd_hash !== expectedSdHash) {
        throw new SDJWTVCError('sd_hash mismatch');
      }
    }

    if (!Object.values(supportedAlgorithm).includes(header.alg as supportedAlgorithm)) {
      throw new SDJWTVCError('unsupported algorithm');
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
      'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3ZhbGlkLnZlcmlmaWVyLnVybCIsIm5vbmNlIjoibklkQmJOZ1JxQ1hCbDhZT2tmVmRnPT0iLCJzZF9oYXNoIjoiTHdvOXZaMHc5SlVkZFlNdEVrc3JVYWc4TnRtY05JNGdFT3JhbzVYT1R6SSIsImlhdCI6MTcwNzE0NzYxNjk3MX0._rdKs3oVlxu6rGtbiBxP69Ammlc4OV6IPvQa9EVI6JUis3Vf5xOofS7xkJDeM5Q8rg00_vQqyQ21eYapyvLMSA',
    nonce: 'nIdBbNgRqCXBl8YOkfVdg==',
  };

  const issuerPubKey = await importJWK({
    crv: 'Ed25519',
    x: 'rc0lLGwZ7qsLvHsCUcd84iGz3-MaKUumZP03JlJjLAs',
    kty: 'OKP',
  });

  const vcSDJWTWithoutKeyBinding: string = vcSDJWTWithkeyBindingJWT.slice(
    0,
    vcSDJWTWithkeyBindingJWT.lastIndexOf('~') + 1,
  );
  const hasher: Hasher = hasherCallbackFn(defaultHashAlgorithm);
  const sdJwtHash: string = hasher(vcSDJWTWithoutKeyBinding);

  const result = await verifier.verifyVCSDJWT(
    vcSDJWTWithkeyBindingJWT,
    verifierCallbackFn(issuerPubKey),
    hasherCallbackFn(defaultHashAlgorithm),
    kbVeriferCallbackFn('https://valid.verifier.url', nonce, sdJwtHash),
  );
  console.log(result);
}
```
