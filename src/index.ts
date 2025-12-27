import manager from './AxiosInstanceManager';
import middleware from './AuthenticatedMiddleware';
import jwtUtils from './jwtUtils';

const AxiosInstanceManager = {
  manager,
  jwtUtils,
  middleware,
};
export default AxiosInstanceManager;

export * from './types/index';
