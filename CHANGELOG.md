# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project (loosely) adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.0.2 - 2023-10-04

### Added

- Added new type called VCClaimsWithVCDataModel that can be used to create VCSDJWT

### Removed

- The CredentialStatus type as it was not properly defined based on the specfications [JWT and CWT Status List](https://datatracker.ietf.org/doc/html/draft-looker-oauth-jwt-cwt-status-list-01)

### Changed

- Updated issuer demo script to use the new type VCClaimsWithVCDataModel

## 0.0.1 - 2023-10-03

Initial version
