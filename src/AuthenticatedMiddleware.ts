import type { TokenMetaDataType } from './AxiosInstanceManager'
import type { RouteLocationNormalizedGeneric, RouteLocationAsRelativeGeneric } from 'vue-router'

// Helper function to validate the token
function isValidToken (tokenMetaData: TokenMetaDataType): boolean {
  try {
    const { issuedAt, refreshExpiresIn } = tokenMetaData

    // Check if the token has an expiration field and if it has expired
    if (
        issuedAt === null ||
        refreshExpiresIn === null ||
        isNaN(issuedAt) ||
        isNaN(refreshExpiresIn) ||
        issuedAt < 0 ||
        refreshExpiresIn < 0
    ) {
      // Token does not have a valid structure
      return false
    }

    // Token is valid
    // Assuming refreshExpiresIn is the number of seconds from the time the token was issued
    const refreshTokenExpiresAt =
      new Date(issuedAt).getTime() +
        refreshExpiresIn * 1000
    return (
      tokenMetaData.refreshExpiresIn === 0 || Date.now() <= refreshTokenExpiresAt
    )
  } catch (error) {
    console.error('Invalid token format:', error)
    return false
  }
}

export default function AuthenticatedMiddleware (to: RouteLocationNormalizedGeneric, tokenMetaData: TokenMetaDataType, loginRoute: RouteLocationAsRelativeGeneric) {
  if ((!tokenMetaData || !isValidToken(tokenMetaData)) && to.name !== loginRoute.name) {
    // If token is not valid or not found, redirect to login
    return loginRoute
  }

  // Continue to the route if token is found or already on login page
  return null
}
