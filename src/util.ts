import { sha256 as sha256Hash } from '@noble/hashes/sha256'
import { concat, fromString, toString } from 'uint8arrays'
export { ripemd160 } from '@noble/hashes/ripemd160'

const u8a = { toString, fromString, concat }

export function sha256(payload: string | Uint8Array): Uint8Array {
  const data = typeof payload === 'string' ? fromString(payload) : payload
  return sha256Hash(data)
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, 'base64url')
}

export function stringToBytes(s: string): Uint8Array {
  return u8a.fromString(s)
}
