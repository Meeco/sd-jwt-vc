# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project (loosely) adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.3.0 - 2024-10-07

### Security

- Upgrade `@meeco/sd-jwt` to version `1.2.1`
- Upgrade development dependencies

## 1.2.2 - 2024-05-15

### Fixed

- Removed unnecessary `isValidUrl` condition check from `audience` parameter in `presentVCSDJWT` method

## 1.2.1 - 2024-03-13

### Fixed

- update `@meeco/sd-jwt` for minor bug-fix

## 1.2.0 - 2024-03-13

### Added

- `SDJsonpath` and `SDJWTDisclosureStruct` from `@meeco/sd-jwt`

## 1.1.0 - 2024-02-19

### Added

- Add parameters to allow adding params to kbjwt header

### Changed

- renamed `revealDisclosure` to `selectDisclosure` in `PresentVCSDJWT` to better reflect the intent of the function

## 1.0.4 - 2024-02-14

### Fixed

- Take response status into account when resolving `/.well-known/jwt-vc-issuer` URLs

## 1.0.3 - 2024-02-14

### Added

- Add fallback to `GET /.well-known/jwt-issuer` in case `GET /.well-known/jwt-vc-issuer` returns error

### Security

- Upgrade development dependencies

## 1.0.2 - 2024-02-14

### Fixed

- fix the `iat` claim when creating a keybinding JWT in `getKeyBindingJWT` method

## 1.0.1 - 2024-02-14

### Fixed

- Correct the wellKnownPath in URL formation in `getIssuerPublicKeyFromWellKnownURI` utility function

## 1.0.0 - 2024-02-14

### Changed

- Rename `/.well-known/jwt-issuer` to `/.well-known/jwt-vc-issuer`

## 0.2.0 - 2024-02-09

### Changed

- `Holder` class added with addition parameter to configure hasher
- Key binding JWT includes `sd_hash` payload attribute

## 0.1.0 - 2024-02-05

### Added

- allow additional header input for the sd-jwt vc creation

## 0.0.9 - 2024-02-01

### Fixed

- update `sd-jwt` dependency
- bugfix: ESM imports

## 0.0.8 - 2023-12-08

### Added

- Added validation that ensures JWT reserved claim keys are not present in both the claims and the disclosure frame.

## 0.0.7 - 2023-12-04

### Changed

- The `CreateSDJWTPayload` type now requires `vct` fields in the payload.
- The optional `status` field has been moved from `VCClaims` to `CreateSDJWTPayload` type.
- Demo scripts have been updated.

### Removed

- Removed the `VCClaimsWithVCDataModel` type, which was specific to the w3c data model, from the VCSDJWT creation process. This change allows for the creation of a VCSDJWT with any data model.

## 0.0.6 - 2023-11-25

### Fixed

- `getIssuerPublicKeyFromWellKnownURI` utility function jwt-issuer discovery URI forming
  - don't ignore `/jwt-issuer` path part that is static and should always be present as per [specification](https://www.ietf.org/archive/id/draft-terbu-oauth-sd-jwt-vc-00.html#section-5)

## 0.0.5 - 2023-11-17

### Changed

- Moved `getIssuerPublicKeyFromWellKnownURI` from `verifier` to `utils`.
- Removed console.log from the `verifyVCSDJWT` method in the `verifier` class.

### Added

- Introduce `SDJWTVCError` generic error class.

## 0.0.4 - 2023-10-18

### Changed

- Enable `sd-jwt` verifications without a keybinding callback function
- Ensure that the JWT contains nonce, aud, and iat when a keybinding is provided in sd-jwt

## 0.0.3 - 2023-10-18

### Changed

- Upgrade `sd-jwt` dependency
- Expect Signer function to return a signature string instead of a signed compactJWT

## 0.0.2 - 2023-10-04

### Added

- Added new type called VCClaimsWithVCDataModel that can be used to create VCSDJWT

### Removed

- The CredentialStatus type as it was not properly defined based on the specfications [JWT and CWT Status List](https://datatracker.ietf.org/doc/html/draft-looker-oauth-jwt-cwt-status-list-01)

### Changed

- Updated issuer demo script to use the new type VCClaimsWithVCDataModel

## 0.0.1 - 2023-10-03

Initial version
