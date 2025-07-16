import manager from './AxiosInstanceManager.js'
import middleware from './AuthenticatedMiddleware.js'
import jwtUtils from './jwtUtils.js'

const AxiosInstanceManager = {
    manager,
    jwtUtils,
    middleware,
}
export default AxiosInstanceManager

export * from './types/index.js'
