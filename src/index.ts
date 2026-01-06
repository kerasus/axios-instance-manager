import manager from './AxiosInstanceManager'
import middleware, { isValidToken } from './AuthenticatedMiddleware'
import jwtUtils from './jwtUtils'

const AxiosInstanceManager = {
  manager,
  jwtUtils,
  middleware,
  isValidToken,
}
export default AxiosInstanceManager

export * from './types/index'
