# SD-JWT-VC

This is an implementation of [SD-JWT VC (I-D version latest)](https://drafts.oauth.net/oauth-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc.html) in typescript.

## Installation

```bash
npm install sd-jwt-vc
```

## Usage

### Issuer

This is a TypeScript class that represents an issuer of Verifiable Credentials (VCs) that can create Signed and Disclosed JWTs (SD JWTs) for VCs. It uses the sd-jwt library to create the SD JWTs.

#### Usage

To use the Issuer class, you need to create an instance of it by passing in a private key, an algorithm, and an optional hasher algorithm. Here's an example:

```typescript
import { generateKeyPair } from 'jose';
import { DisclosureFrame, SDJWTPayload } from 'sd-jwt';
import { Issuer } from './issuer';
import { VCClaims } from './types';
import { supportedAlgorithm } from './util';


const keyPair = await generateKeyPair(algorithm);
const privateKey = keyPair.privateKey;
const algorithm: supportedAlgorithm = supportedAlgorithm.EdDSA';
const issuer = new Issuer(privateKey, algorithm, 'sha256');
```

- privateKey: The private key to use for signing the SD JWTs.
- algorithm: The algorithm to use for signing the SD JWTs. Must be one of the supported algorithms ('EdDSA', 'ES256', 'ES256K', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512').
- hasherAlgo: The algorithm to use for hashing the SD JWTs. Must be one of the available algorithms supported by OpenSSL.

#### createVCSDJWT

Once you have an instance of the Issuer class, you can use it to create SD JWTs for VCs. Here's an example:

```typescript
const holderPublicKey = {
  kty: 'EC',
  x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
  y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
  crv: 'P-256',
};

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

const jwt = await issuer.createVCSDJWT(vcClaims, payload, sdVCClaimsDisclosureFrame);
```

This will create an SD JWT for the given VC claims and SD JWT payload for given [disclosure frame](https://github.com/Meeco/sd-jwt#packsdjwt-examples).

### Holder

This is a TypeScript class that represents a holder of Verifiable Credentials (VCs) that can verify Signed and Present SD JWT VC's with Key Binding to Verifier.

#### Usage

To use the Holder class, you need to create an instance of it by passing in a public key, an algorithm, and an optional hasher algorithm. Here's an example:

```typescript
import { generateKeyPair, importJWK } from 'jose';
import { Holder } from './holder';
import { supportedAlgorithm } from './util';


const privateKeyJWK = {
  kty: 'EC',
  x: 'rH7OlmHqdpNOR2P28S7uroxAGk1321Nsgxgp4x_Piew',
  y: 'WGCOJmA7nTsXP9Az_mtNy0jT7mdMCmStTfSO4DjRsSg',
  crv: 'P-256',
  d: '9Ie2xvzUdQBGCjT9ktsZYGzwG4hOWea-zvCQSQSWJxk',
};

const privateKey = await importJWK(privateKeyJWK);
const algorithm: supportedAlgorithm = supportedAlgorithm.ES256';
const holder = new Holder(privateKey, supportedAlgorithm.ES256);
```

#### presentVerifiableCredentialSDJWT

```typescript
const issuedSDJWT =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE2OTU2ODI0MDg4NTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4Ijoickg3T2xtSHFkcE5PUjJQMjhTN3Vyb3hBR2sxMzIxTnNneGdwNHhfUGlldyIsInkiOiJXR0NPSm1BN25Uc1hQOUF6X210TnkwalQ3bWRNQ21TdFRmU080RGpSc1NnIiwiY3J2IjoiUC0yNTYifX0sImlzcyI6Imh0dHBzOi8vdmFsaWQuaXNzdWVyLnVybCIsInR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsInN0YXR1cyI6eyJpZHgiOiJzdGF0dXNJbmRleCIsInVyaSI6Imh0dHBzOi8vdmFsaWQuc3RhdHVzLnVybCJ9LCJwZXJzb24iOnsiX3NkIjpbImNRbzBUTTdfZEZXb2djcUpUTlJPeGJUTnI1T0VaakNWUHNlVVBVN0ROa3ciLCJZY3BHVTNKTDFvS0NoOXY4VjAwQmxWLTQtZTFWN1h0U1BvYUtra2RuZG1BIl19fQ.iPmq7Fv-pxS5NgTpH5xUarz6uG1MIphHy4q5mWdLBJRfp6ER2eG306WeHhCBoDzrYURgWZiEySnTEBDbD2HfCA~WyJNcEFKRDhBWVBQaEJhT0tNIiwibmFtZSIsInRlc3QgcGVyc29uIl0~WyJJbFl3RkV5WDlLSFVIU1NFIiwiYWdlIiwyNV0~';

const { vcSDJWTWithkeyBindingJWT, nonce } = await holder.presentVerifiableCredentialSDJWT(
  'https://valid.verifier.url',
  issuedSDJWT,
);
```

This will create an SD JWT VC with Key Binding JWT. The holder can then send this JWT to the verifier.
