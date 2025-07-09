@ada/axios-instance-manager
A Vue 3 and Axios-based instance manager for handling API tokens and requests with caching and token refresh capabilities.
Installation
npm install @your-org/axios-instance-manager

Usage
Configuration
import AxiosInstanceManager from '@your-org/axios-instance-manager';

const config = {
mainScopes: 'your-scopes',
mainServiceName: 'your-service',
frontendApiBase: 'https://api.example.com',
tokenDataInLoacalStoragePrefix: 'token_',
getMainTokenAddress: '/auth/token',
getRefreshTokenAddress: '/auth/refresh',
serverMessagesPrefix: 'server',
localStorageKeyPrefix: 'app_',
tokenMetaDataKeyInCookie: 'tokenMetaData',
getServiceTokenAddress: (serviceName: string) => `/auth/service/${serviceName}`,
setUser: (decodedToken: Record<string, any>) => {
console.log('User set:', decodedToken);
},
goToLoginPage: () => {
window.location.href = '/login';
}
};

const axiosInstanceManager = AxiosInstanceManager(config);

// Add an instance for a specific service
axiosInstanceManager.addInstance('myService', 'read write');

// Make a request
const instance = axiosInstanceManager.getInstance('myService', 'read write');
instance.get('/some-endpoint').then(response => {
console.log(response.data);
});

API
AxiosInstanceManager(config)
Creates an instance manager with the provided configuration.

config: Configuration object with properties like mainScopes, mainServiceName, frontendApiBase, etc.

Methods

addInstance(serviceName: string, scopes: string): Adds a new Axios instance for the specified service and scopes.
getInstance(serviceName: string, scopes: string): Retrieves an Axios instance for the specified service and scopes.
getToken(serviceName: string, scopes: string): Retrieves the access token for the specified service and scopes.
setCredentials(username: string, password: string, captcha: string): Sets the credentials for obtaining the main token.
obtainMainToken(): Obtains the main token using the provided credentials.
logout(): Clears all tokens and credentials.
getWithCache(url: string, config?: AxiosRequestConfig): Makes a GET request with caching.

License
MIT