# sd-jwt-vc

Create and verify W3C Verifiable Credentials and Presentations in SD JWT format

## Installation

```
npm install sd-jwt-vc
```

## Usage

### Creating SD JWTs

#### Prerequisites

Create an `Issuer` object to sign SD JWTs

```typescript

```

The `Issuer` object must contain an `alg`, `publicKeyJwk` &  `privateKeyJwk` property that is used in the JWT header and a `signer`
function to generate the signature.

#### Creating a Verifiable Credential

Specify a `payload` matching the `SdJwtCredentialPayload` interfaces. Create a JWT by signing it
with the previously configured `issuer` using the `createVerifiableCredentialSdJwt` function:

```typescript

```

#### Creating a Verifiable Presentation

Specify a `payload` matching the `SdJwtPresentationPayload` interfaces, including the VC SD JWTs to
be presented in the `vp.verifiableCredential` array. Create a JWT by signing it with the previously configured `issuer`
using the `createVerifiablePresentationSdJwt` function:

```typescript

```

### Verifying JWTs


#### Verifying a Verifiable Credential

Pass in a VC JWT along with the resolver to verify using the `verifySdJwtCredential` function:

```typescript


```

#### Verifying a Verifiable Presentation

Pass in a VP JWT along with the resolver to verify using the `verifySdJwtPresentation` function:

```typescript

```

