import { JWK, decodeJWT } from '@meeco/sd-jwt';
import { SDJWTVCError } from './errors.js';
import { JWT, SD_JWT_FORMAT_SEPARATOR } from './types.js';

export enum ValidTypValues {
  VCSDJWT = 'vc+sd-jwt',
  DCSDJWT = 'dc+sd-jwt',
}

export enum supportedAlgorithm {
  EdDSA = 'EdDSA',
  ES256 = 'ES256',
  ES256K = 'ES256K',
  ES384 = 'ES384',
  ES512 = 'ES512',
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',
}

export const defaultHashAlgorithm = 'sha256';

export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get the issuer public key from the issuer.
 * @param sdJwtVC The SD-JWT to verify.
 * @param issuerPath The issuer path postfix to /.well-known/jwt-vc-issuer/{issuerPath}, to get the issuer public key. e.g. 'jwt-issuer/user/1234'
 * @throws An error if the issuer public key cannot be fetched.
 * @returns The issuer public key.
 */
export async function getIssuerPublicKeyFromWellKnownURI(sdJwtVC: JWT, issuerPath: string): Promise<JWK> {
  const s = sdJwtVC.split(SD_JWT_FORMAT_SEPARATOR);
  const jwt = decodeJWT(s.shift() || '');

  if (!jwt.payload.iss || !isValidUrl(jwt.payload.iss)) {
    throw new SDJWTVCError('Invalid issuer well-known URL');
  }

  const url = new URL(jwt.payload.iss);
  const baseUrl = `${url.protocol}//${url.host}`;
  const issuerUrl = `${baseUrl}/.well-known/jwt-vc-issuer/${issuerPath}`;

  const [responseJson, error] = await fetch(issuerUrl)
    .then(async (response) => {
      const body = await response.json();

      if (!response.ok) {
        throw new Error(JSON.stringify(body));
      }

      return [body, null];
    })
    .catch(async (err) => {
      /**
       * @deprecated
       * In favor of: https://drafts.oauth.net/oauth-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc.html#name-jwt-vc-issuer-metadata
       * To stay compatible with the old spec, check on the /.well-known/jwt-issuer/ endpoint is still being done if /.well-known/jwt-vc-issuer/ returned an error.
       * No one should rely on this functionality, it will be removed at some point later.
       */
      const issuerFallbackUrl = `${baseUrl}/.well-known/jwt-issuer/${issuerPath}`;

      console.warn(
        `GET request to ${issuerUrl} has failed. Falling back to ${issuerFallbackUrl}. Fallback URL is here to support older version of the specification. You should not rely on this functionality being here. It will be removed at some point in the future.`,
      );

      return fetch(issuerFallbackUrl)
        .then(async (response) => {
          const body = await response.json();

          if (!response.ok) {
            throw new Error(JSON.stringify(body));
          }

          return [body, null];
        })
        .catch((fallbackErr) => {
          return [
            null,
            new SDJWTVCError(
              `Failed to fetch and parse the response from ${issuerUrl} as JSON. Error: ${err.message}. Fallback fetch and parse the response from ${issuerFallbackUrl} failed as well. Error: ${fallbackErr.message}.`,
            ),
          ];
        });
    });

  if (error) {
    throw error;
  }
  if (!responseJson) {
    throw new SDJWTVCError('Issuer response not found');
  }
  if (!responseJson.issuer || responseJson.issuer !== jwt.payload.iss) {
    throw new SDJWTVCError("The response from the issuer's well-known URI does not match the expected issuer");
  }

  let issuerPublicKeyJWK: JWK | undefined;

  if (responseJson.jwks_uri) {
    const jwksResponse = await fetch(responseJson.jwks_uri);
    const jwksResponseJson = await jwksResponse.json();
    issuerPublicKeyJWK = getIssuerPublicKeyJWK(jwksResponseJson, jwt.header.kid);
  } else {
    issuerPublicKeyJWK = getIssuerPublicKeyJWK(responseJson.jwks, jwt.header.kid);
  }

  if (!issuerPublicKeyJWK) {
    throw new SDJWTVCError('Issuer public key JWK not found');
  }

  return issuerPublicKeyJWK;
}

/**
 * Gets the issuer public key JWK.
 * @param jwks The jwks to use.
 * @param kid The kid to use.
 * @throws An error if the issuer public key JWK cannot be found.
 * @returns The issuer public key JWK.
 */
export function getIssuerPublicKeyJWK(jwks: any, kid?: string): JWK | undefined {
  if (!jwks || !jwks.keys) {
    throw new SDJWTVCError('Issuer response does not contain jwks or jwks_uri');
  }

  if (kid) {
    return jwks.keys.find((key: any) => key.kid === kid);
  } else {
    return jwks.keys[0];
  }
}
