import type { RouteLocationNormalizedGeneric, RouteLocationAsRelativeGeneric } from 'vue-router'
import type { TokenMetaDataType } from './types'

// Helper function to validate the token
export function isValidToken (tokenMetaData: TokenMetaDataType): boolean {
  try {
    const { issuedAt, expiresIn, mfaEnabled, mfaVerified } = tokenMetaData

    if (
      issuedAt === null ||
        expiresIn === null ||
        isNaN(issuedAt) ||
        isNaN(expiresIn) ||
        issuedAt < 0 ||
        expiresIn < 0
    ) {
      // Token does not have a valid structure
      return false
    }

    const isExpired = (Date.now() / 1000) >= (issuedAt + expiresIn)
    if (isExpired) {
      return false
    }

    return !(mfaEnabled && !mfaVerified)
  } catch (error) {
    console.error('Invalid token format:', error)
    return false
  }
}

export default function middleware (
  to: RouteLocationNormalizedGeneric,
  tokenMetaData: TokenMetaDataType,
  loginRoute: RouteLocationAsRelativeGeneric,
): RouteLocationAsRelativeGeneric | null | undefined {
  if ((!tokenMetaData || !isValidToken(tokenMetaData)) && to.name !== loginRoute.name) {
    // If a token is not valid or not found, redirect to log in
    return loginRoute
  }

  // Continue to the route if a token is found or already on the login page
  return null
}
