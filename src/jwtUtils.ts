import { Buffer } from 'buffer'
import type { DecodedJwtObjectType } from './types'

// Function to decode JWT without verification
function getDecodeJwt (token: string): DecodedJwtObjectType | null {
  // Helper function to decode base64url
  function base64urlDecode (str: string): string {
    // Replace non-url compatible chars with base64 standard chars
    str = str.replace(/-/g, '+').replace(/_/g, '/')

    // Pad with trailing '=' to make length of the string a multiple of 4
    while (str.length % 4) {
      str += '='
    }

    // Decode base64 string
    const decodedStr = Buffer.from(str, 'base64').toString('utf8')
    return decodedStr
  }
  try {
    const [header, payload, signature] = token.split('.')

    if (!header || !payload || !signature) {
      throw new Error('Invalid token format')
    }

    const decodedHeader = JSON.parse(base64urlDecode(header))
    const decodedPayload = JSON.parse(base64urlDecode(payload))

    return {
      header: decodedHeader,
      payload: decodedPayload,
      signature
    }
  } catch (error) {
    console.error('Failed to decode token:', error)
    return null
  }
}

const jwtUtils = {
  getDecodeJwt
}

export default jwtUtils
