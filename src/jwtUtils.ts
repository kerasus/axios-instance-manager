import { Buffer } from 'buffer'

export type AuthObjectType = {
  accessToken: string
  refreshToken: string
  sessionState: string
  userId: number
  expiresIn: number
  refresh_expires_in: number
}

export type DecodedJwtObjectType = {
  header: {
    alg: string
    kid: string
    typ: string
  }
  payload: {
    aud: string[]
    azp: string
    email: string
    email_verified: boolean
    exp: number
    family_name: string
    given_name: string
    iss: string
    jti: string
    name: string
    preferred_username: string
    realm_access: {
      roles: string[]
    }
    resource_access: {
      account: {
        roles: string[]
      }
      'realm-management': {
        roles: string[]
      }
      scope: string
      session_state: string
      sid: string
      sub: string
      typ: string
    }
    scope: string
    session_state: string
    sid: string
    ledgerId: number
    sub: string
    typ: string
  }
  signature: string
}

export const tokenType = 'Bearer'

// Function to decode JWT without verification
export function getDecodeJwt (token: string): DecodedJwtObjectType | null {
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

export default {
  getDecodeJwt
}
