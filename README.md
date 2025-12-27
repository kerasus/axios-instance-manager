@ada/axios-instance-manager
A Vue 3 and Axios-based instance manager for handling API tokens and requests with caching and token refresh capabilities.

Installation
```bash
npm install @ada/axios-instance-manager
```

Usage
Configuration
```typescript
import AxiosInstanceManager from '@ada/axios-instance-manager';

const config = {
  mainScopes: 'your-scopes',
  mainServiceName: 'your-service',
  frontendApiBase: 'https://api.example.com',
  tokenDataInLocalStoragePrefix: 'token_',
  getMainTokenAddress: '/auth/token',
  getRefreshTokenAddress: '/auth/refresh',
  localStorageKeyPrefix: 'app_',
  tokenMetaDataKeyInCookie: 'tokenMetaData',
  getServiceTokenAddress: (serviceName: string) => `/auth/service/${serviceName}`,
  setUser: async (decodedToken: Record<string, any>) => {
    console.log('User set:', decodedToken);
  },
  afterLogout: async () => {
    console.log('After logout');
  },
  beforeLogout: async () => {
    console.log('Before logout');
  },
  handleResponseErrors: async (error) => {
    console.error('Response error:', error);
  },
  logLevel: 'error'
};

const axiosInstanceManager = AxiosInstanceManager.manager(config);

// Add an instance for a specific service
axiosInstanceManager.addInstance('myService', 'read write');

// Make a request
const instance = axiosInstanceManager.getInstance('myService', 'read write');
instance.get('/some-endpoint').then(response => {
  console.log(response.data);
});
```

API
`AxiosInstanceManager.manager(config)`
Creates an instance manager with the provided configuration.

`config`: Configuration object with properties like `mainScopes`, `mainServiceName`, `frontendApiBase`, etc.

Methods

`addInstance(serviceName: string, scopes: string)`: Adds a new Axios instance for the specified service and scopes.
`getInstance(serviceName: string, scopes: string)`: Retrieves an Axios instance for the specified service and scopes.
`getToken(serviceName: string, scopes: string)`: Retrieves the access token for the specified service and scopes.
`setCredentials(username: string, password: string, captcha?: string, otp?: string)`: Sets the credentials for obtaining the main token.
`obtainMainToken()`: Obtains the main token using the provided credentials.
`logout()`: Clears all tokens and credentials.
`getWithCache(url: string, config?: AxiosRequestConfig)`: Makes a GET request with caching.

Development
Available Scripts
`npm run lint`: Runs ESLint to check for code style and potential errors.
`npm run lint:fix`: Runs ESLint and automatically fixes fixable issues.
`npm run type-check`: Runs TypeScript type checking without emitting files.
`npm run build`: Builds the project for production.

License
MIT