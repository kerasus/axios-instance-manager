import { ref } from 'vue'
import axios from 'axios'
import type {
  AxiosResponse,
  AxiosInstance,
  InternalAxiosRequestConfig,
} from 'axios'
import jwtUtils from './jwtUtils'
import { createLogger } from './logger'
import type {
  TokenData,
  CacheEntry,
  TokenMetaDataType,
  ServiceResponseError,
  AxiosInstanceManagerConfigType,
} from './types'

export class AuthError extends Error {
  constructor (message?: string) {
    super(message ?? 'Authentication error')
    this.name = 'AuthError'
  }
}

let instance: ReturnType<typeof createInstance> | null = null
let isLoggedOut = false

const cache = new Map<string, CacheEntry>()
const pendingRequests = new Map<string, { promise: Promise<AxiosResponse>, createdAt: number }>()

const PENDING_REQUEST_TTL = 1000 * 30
const CACHE_CLEANUP_INTERVAL = 1000 * 60 * 5

setInterval(() => {
  const now = Date.now()
  for (const [url, entry] of cache.entries()) {
    if (entry.expiry <= now) {
      cache.delete(url)
    }
  }
  for (const [url, req] of pendingRequests.entries()) {
    if (now - req.createdAt > PENDING_REQUEST_TTL) {
      pendingRequests.delete(url)
    }
  }
}, CACHE_CLEANUP_INTERVAL)

function getCachedData (url: string): AxiosResponse | null {
  const cacheEntry = cache.get(url)
  if (cacheEntry) {
    if (cacheEntry.expiry > Date.now()) {
      // Cache is still valid
      return {
        data: cacheEntry.data,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {},
      } as AxiosResponse
    } else {
      // Cache has expired
      cache.delete(url)
    }
  }
  return null
}

function cacheData (url: string, response: AxiosResponse, ttl: number): void {
  cache.set(url, {
    data: response.data,
    expiry: Date.now() + ttl,
  })
}

function createInstance (axiosInstanceManagerConfig: AxiosInstanceManagerConfigType): {
  logout: () => Promise<void>;
  getToken: (serviceName: string, scopes: string) => Promise<string | null | undefined>;
  addInstance: (serviceName: string, scopes: string) => void;
  getInstance: (serviceName: string, scopes: string) => AxiosInstance;
  setCredentials: (username: string, password: string, captcha?: string, otp?: string) => void;
  obtainMainToken: () => Promise<AxiosResponse<TokenData>>;
  getSavedTokenData: (serviceName: string, scopes: string) => TokenData | null;
  createRawInstance: (baseURL?: string) => AxiosInstance;
  verifyMainTokenMfa: (otp: string) => Promise<void>;
  markMainTokenMfaVerified: (serviceName: string, scopes: string) => void;
  getMainTokenDataFromCookie: () => TokenMetaDataType | null;
  getTokenDataFromLocalStorage: (serviceName: string, scopes: string) => TokenData | null;
} {
  const mainScopes = axiosInstanceManagerConfig.mainScopes
  const mainServiceName = axiosInstanceManagerConfig.mainServiceName
  const logoutScopes = axiosInstanceManagerConfig.logoutScopes
  const logoutServiceName = axiosInstanceManagerConfig.logoutServiceName
  const frontendApiBase = axiosInstanceManagerConfig.frontendApiBase
  const tokenMetaDataKeyInCookie = axiosInstanceManagerConfig.tokenMetaDataKeyInCookie
  const tokenDataInLocalStoragePrefix = axiosInstanceManagerConfig.tokenDataInLocalStoragePrefix
  const getMainTokenAddress = axiosInstanceManagerConfig.getMainTokenAddress
  const getRefreshTokenAddress = axiosInstanceManagerConfig.getRefreshTokenAddress
  const verifyMainTokenMfaAddress = axiosInstanceManagerConfig.verifyMainTokenMfaAddress
  const logoutAddress = axiosInstanceManagerConfig.logoutAddress
  const getServiceTokenAddress = axiosInstanceManagerConfig.getServiceTokenAddress
  const handleResponseErrors = axiosInstanceManagerConfig.handleResponseErrors

  const logger = createLogger(axiosInstanceManagerConfig.logLevel || 'error')

  const instances = new Map<string, AxiosInstance>()
  const tokens = new Map<string, TokenData | null>()
  const credentials = ref<{
        username: string | null
        password: string | null
        captcha?: string | null
        otp?: string | null
    }>({
      username: null,
      password: null,
      captcha: null,
      otp: null,
    })
  let refreshTokenPromise: Promise<void> | null = null

  const mainInstanceKey = getMainInstanceKey()
  tokens.set(mainInstanceKey, getTokenDataFromLocalStorage(mainServiceName, mainScopes))

  function getLocalStorageKey (serviceName: string, scopes: string): string {
    const instanceKey = getInstanceKey(serviceName, scopes)

    return `${axiosInstanceManagerConfig.localStorageKeyPrefix}_${tokenDataInLocalStoragePrefix}${instanceKey}`
  }

  function saveTokenData (serviceName: string, scopes: string, tokenData: TokenData): void {
    if (typeof window === 'undefined') {
      return
    }
    const mainInstanceKey = getMainInstanceKey()
    const instanceKey = getInstanceKey(serviceName, scopes)
    const localStorageKey = getLocalStorageKey(serviceName, scopes)
    localStorage.setItem(localStorageKey, JSON.stringify(tokenData))
    if (mainInstanceKey === instanceKey) {
      saveTokenDataToCookie({
        tokenType: tokenData.tokenType,
        expiresIn: tokenData.expiresIn,
        refreshExpiresIn: tokenData.refreshExpiresIn,
        mfaEnabled: tokenData.mfaEnabled,
        mfaVerified: tokenData.mfaVerified,
        issuedAt: tokenData.issuedAt,
      })
    }
  }

  function markMainTokenMfaVerified (): void {
    const mainInstanceKey = getMainInstanceKey()
    const mainTokenData = tokens.get(mainInstanceKey)

    if (!mainTokenData) {
      return
    }

    mainTokenData.mfaEnabled = true
    mainTokenData.mfaVerified = true
    tokens.set(mainInstanceKey, mainTokenData)

    if (typeof window === 'undefined') {
      return
    }
    const localStorageKey = getLocalStorageKey(mainServiceName, mainScopes)
    localStorage.setItem(localStorageKey, JSON.stringify(mainTokenData))
    saveTokenDataToCookie({
      tokenType: mainTokenData.tokenType,
      expiresIn: mainTokenData.expiresIn,
      refreshExpiresIn: mainTokenData.refreshExpiresIn,
      mfaEnabled: mainTokenData.mfaEnabled,
      mfaVerified: mainTokenData.mfaVerified,
      issuedAt: mainTokenData.issuedAt,
    })
  }

  async function verifyMainTokenMfa (otp: string): Promise<void> {
    if (isLoggedOut) {
      logger.warn('verify aborted: user logged out')
      return
    }

    const mainInstanceKey = getMainInstanceKey()
    const mainTokenData = tokens.get(mainInstanceKey)

    if (!mainTokenData || !mainTokenData.mfaEnabled) {
      throw new AuthError('No refresh token available for MainService')
    }

    const mainToken = mainTokenData.accessToken
    if (!mainToken) {
      throw new Error('Main token is not available to verify it\'s mfa')
    }

    try {

      const instanceForVerifyMainTokenMfa = axios.create({
        headers: {
          Authorization: `Bearer ${mainToken}`,
        },
      })

      await instanceForVerifyMainTokenMfa.patch<TokenData>(verifyMainTokenMfaAddress, {
        username: credentials.value.username,
        otp: otp,
      })
      markMainTokenMfaVerified()
      await setAuthenticatedUserData()
    } catch (error) {
      logger.error('MFA Verification Error:', error)
      if (error instanceof AuthError) {
        throw error
      }
      if (axios.isAxiosError(error) && error.response) {
        const status = error.response.status
        const data = error.response.data as ServiceResponseError

        if (status === 401) {
          throw new AuthError('MFA verification failed')
        }

        const detail = data?.detail?.[0]
        const message = detail?.type || error.message || 'MFA verification failed: Unexpected error'
        throw new Error(message)
      }

      throw new Error('MFA verification failed: Unexpected error')
    } finally {
      refreshTokenPromise = null
    }
  }

  function getTokenDataFromLocalStorage (serviceName: string, scopes: string): TokenData | null {
    if (typeof window === 'undefined') {
      return null
    }
    const localStorageKey = getLocalStorageKey(serviceName, scopes)
    const data = localStorage.getItem(localStorageKey)
    if (!data) {
      return null
    }

    try {
      return JSON.parse(data) as TokenData
    } catch (err) {
      logger.error(`Failed to parse token data from localStorage for key "${localStorageKey}":`, err)
      return null
    }
  }

  function setCredentials (username: string, password: string, captcha?: string, otp?: string): void {
    credentials.value.username = username
    credentials.value.password = password
    credentials.value.captcha = captcha
    credentials.value.otp = otp

    isLoggedOut = false
  }

  function getSavedTokenData (serviceName: string, scopes: string): TokenData | null {
    const instanceKey = getInstanceKey(serviceName, scopes)
    const loaded = getTokenDataFromLocalStorage(serviceName, scopes)
    if (loaded) {
      tokens.set(instanceKey, loaded)
    }
    return tokens.get(instanceKey) ?? null
  }

  async function getToken (serviceName: string, scopes: string): Promise<string | null | undefined> {
    const instanceKey = getInstanceKey(serviceName, scopes)
    let tokenData = getSavedTokenData(serviceName, scopes)

    if (!tokenData?.accessToken && instanceKey === getMainInstanceKey()) {
      throw new Error('Failed to obtain main token')
    }

    if (serviceName === mainServiceName && scopes === mainScopes) {
      throw new Error('Cannot obtain main service token via obtainServiceToken')
    }

    try {
      if (!tokenData?.accessToken) {
        tokenData = await obtainServiceToken(serviceName, scopes)
        tokens.set(instanceKey, tokenData)
        saveTokenData(serviceName, scopes, tokenData)
        return tokenData.accessToken
      }
      return tokenData.accessToken
    } catch (error) {
      logger.error(`Error getting token for serviceName: "${serviceName}", scopes: "${scopes}":`, error)
      throw error instanceof Error ? error : new Error('Unexpected error getting token')
    }
  }

  function saveTokenDataToCookie (tokenMetaData: TokenMetaDataType): void {
    if (typeof window === 'undefined') {
      return
    }
    const tokenMetaDataString = JSON.stringify(tokenMetaData)

    // Set the cookie with the token data
    document.cookie = `${axiosInstanceManagerConfig.tokenMetaDataKeyInCookie}=${encodeURIComponent(tokenMetaDataString)}; path=/; SameSite=Strict;`

    // // Optionally, set an expiration date for the cookie
    // const expires = new Date()
    // expires.setTime(expires.getTime() + (tokenData.refreshExpiresIn * 1000)) // assuming refreshExpiresIn is in seconds
    // document.cookie = `${tokenMetaDataKeyInCookie}=${encodeURIComponent(tokenDataString)}; path=/; expires=${expires.toUTCString()}; SameSite=Strict;`
  }

  function getMainTokenDataFromCookie (): TokenMetaDataType | null {
    if (typeof window === 'undefined') {
      return null
    }
    if (!document.cookie) {
      return null
    }

    const name = `${tokenMetaDataKeyInCookie}=`
    const decodedCookie = decodeURIComponent(document.cookie)
    const cookieArr = decodedCookie.split(';').filter((item)=>!!item)
    const cookieArrCount = cookieArr.length
    for (let i = 0; i < cookieArrCount; i++) {
      const cookie = cookieArr[i].trim()
      if (cookie.indexOf(name) === 0) {
        const cookieValue = cookie.substring(name.length, cookie.length)
        try {
          return JSON.parse(cookieValue) as TokenMetaDataType
        } catch {
          return null
        }
      }
    }

    return null
  }

  function getObtainServiceTokenPayload (token: string): any {
    return { accessToken: token }
  }

  async function obtainMainToken (): Promise<AxiosResponse<TokenData>> {
    if (isLoggedOut) {
      logger.warn('obtainMainToken aborted: user logged out')
      return Promise.reject(new Error('User logged out'))
    }

    if (
      !credentials.value.username ||
            !credentials.value.password
    ) {
      throw new Error('Credentials are not set')
    }

    try {
      const response = await axios.post<TokenData>(getMainTokenAddress, {
        username: credentials.value.username,
        password: credentials.value.password,
        captcha: credentials.value.captcha,
        otp: credentials.value.otp,
      })
      clearTokens()
      const data: TokenData = {
        serviceName: mainServiceName,
        scopes: mainScopes,
        accessToken: response.data.accessToken,
        refreshToken: response.data.refreshToken,
        tokenType: response.data.tokenType,
        expiresIn: response.data.expiresIn,
        otpExpiresIn: response.data.otpExpiresIn,
        mfaEnabled: !!response.data.otpExpiresIn,
        mfaVerified: false,
        refreshExpiresIn: response.data.refreshExpiresIn,
        issuedAt: Date.now(),
      }
      const mainInstanceKey = getMainInstanceKey()
      tokens.set(mainInstanceKey, data)
      saveTokenData(mainServiceName, mainScopes, data)

      // Save token data to cookie and use that in
      // Authenticated middleware for ssr mode
      saveTokenDataToCookie({
        tokenType: data.tokenType,
        expiresIn: data.expiresIn,
        refreshExpiresIn: data.refreshExpiresIn,
        mfaEnabled: data.mfaEnabled,
        mfaVerified: data.mfaVerified,
        issuedAt: Date.now(),
      })
      await setAuthenticatedUserData()

      response.data = data
      return response
    } catch (error) {
      logger.error('Error obtaining main token:', error)
      // Explicitly reject the promise by throwing an error
      throw error
    }
  }

  async function obtainServiceToken (serviceName: string, scopes: string): Promise<TokenData> {
    if (serviceName === mainServiceName && scopes === mainScopes) {
      throw new Error('obtainServiceToken should not be used to obtain the main service token')
    }

    const mainInstanceKey = getMainInstanceKey()
    let mainTokenData = tokens.get(mainInstanceKey) ?? getTokenDataFromLocalStorage(mainServiceName, mainScopes)

    try {
      if (!mainTokenData || !mainTokenData.accessToken) {
        const mainTokenResponse = await obtainMainToken()
        mainTokenData = mainTokenResponse.data
      }
    } catch (error) {
      logger.error(
        `Error obtaining main token for getting token of serviceName: "${serviceName}", scopes: "${scopes}":`,
        error,
      )
      throw error
    }

    const mainToken = mainTokenData.accessToken
    if (!mainToken) {
      throw new Error('Main token is not available after attempting to obtain it')
    }

    try {
      const instanceForObtainServiceToken = axios.create({
        baseURL: frontendApiBase, // Set baseURL from environment variable
        headers: {
          Authorization: `Bearer ${mainToken}`,
        },
      })

      instanceForObtainServiceToken.interceptors.response.use(
        (response) => response,
        async (error: unknown) => {
          if (axios.isAxiosError(error)) {
            const originalRequest = error.config as { _retry?: boolean; data?: string } & Record<string, any>
            if (error.response && error.response.status === 401 && !originalRequest?._retry) {
              originalRequest._retry = true

              try {
                await refreshToken()
                const refreshedMain = tokens.get(mainInstanceKey) ?? getTokenDataFromLocalStorage(mainServiceName, mainScopes)
                const refreshedMainAccess = refreshedMain?.accessToken
                if (refreshedMainAccess) {
                  originalRequest.data = JSON.stringify(getObtainServiceTokenPayload(refreshedMainAccess))
                  return instanceForObtainServiceToken(originalRequest as InternalAxiosRequestConfig)
                }
              } catch (refreshError) {
                logger.error(`Error refreshing token while obtaining service token for "${serviceName}":`, refreshError)
                return Promise.reject(refreshError)
              }
            }
          }
          return Promise.reject(error)
        },
      )

      const response = await instanceForObtainServiceToken.put<TokenData>(
        getServiceTokenAddress(serviceName),
        getObtainServiceTokenPayload(mainToken),
        {
          params: { scopes },
        },
      )

      const tokenData: TokenData = {
        serviceName,
        scopes,
        accessToken: response.data.accessToken,
        refreshToken: response.data.refreshToken,
        tokenType: response.data.tokenType,
        expiresIn: response.data.expiresIn,
        mfaEnabled: !!response.data.otpExpiresIn,
        mfaVerified: false,
        refreshExpiresIn: response.data.refreshExpiresIn,
        issuedAt: Date.now(),
      }
      saveTokenData(serviceName, scopes, tokenData)
      return tokenData
    } catch (error) {
      logger.error(
        `Error obtaining token for serviceName: "${serviceName}", scopes: "${scopes}":`,
        error,
      )
      throw new Error(`Failed to obtain token for service "${serviceName}", scopes "${scopes}"`)
    }
  }

  function clearTokens (): void {
    tokens.clear()

    if (typeof window !== 'undefined') {
      clearLocalStorageKeysWithPrefix(axiosInstanceManagerConfig.localStorageKeyPrefix)
      deleteTokenMetaDataFromCookie()
    }
  }

  async function setAuthenticatedUserData (): Promise<void> {
    if (typeof axiosInstanceManagerConfig.setUser !== 'function') {
      return
    }

    const mainInstanceKey = getMainInstanceKey()
    const mainTokenData = tokens.get(mainInstanceKey)
    if (mainTokenData && mainTokenData.accessToken) {
      const token = mainTokenData.accessToken
      const decodedToken = jwtUtils.getDecodeJwt(token)
      if (decodedToken) {
        await axiosInstanceManagerConfig.setUser(mainTokenData, decodedToken)
      }
    }
  }

  async function refreshToken (): Promise<void> {
    if (isLoggedOut) {
      logger.warn('Refresh aborted: user logged out')
      return
    }

    if (refreshTokenPromise) {
      return refreshTokenPromise
    }

    refreshTokenPromise = (async () => {
      if (isLoggedOut) {
        return
      }
      const mainInstanceKey = getMainInstanceKey()
      const mainTokenData = tokens.get(mainInstanceKey)

      if (!mainTokenData || !mainTokenData.refreshToken) {
        throw new AuthError(`No refresh token available for MainService: "${mainServiceName}"`)
      }

      try {
        const response = await axios.put<TokenData>(getRefreshTokenAddress, {
          refreshToken: mainTokenData.refreshToken,
        })

        if (isLoggedOut) {
          return // avoid overwriting after logout
        }

        clearTokens()

        // Update main token with the new access token and refresh token
        tokens.set(mainInstanceKey, {
          serviceName: mainServiceName,
          scopes: mainScopes,
          accessToken: response.data.accessToken,
          refreshToken: response.data.refreshToken,
          tokenType: response.data.tokenType,
          expiresIn: response.data.expiresIn,
          refreshExpiresIn: response.data.refreshExpiresIn,
          mfaEnabled: !!response.data.otpExpiresIn,
          mfaVerified: false,
          issuedAt: Date.now(),
        })

        // Save the new tokens in local storage
        saveAllTokensData()
        await setAuthenticatedUserData()
      } catch (error) {
        logger.error('Error refreshing token', error)
        if (error instanceof AuthError) {
          throw error
        }
        throw new Error('Error refreshing token: Unexpected error')
      } finally {
        refreshTokenPromise = null
      }
    })()

    return refreshTokenPromise
  }

  function saveAllTokensData (): void {
    for (const [, tokenItem] of tokens.entries()) {
      if (!tokenItem) {
        continue
      }

      const { serviceName, scopes } = tokenItem
      if (serviceName && scopes) {
        saveTokenData(serviceName, scopes, tokenItem)
      }
    }
  }

  function createRawInstance (baseURL?: string): AxiosInstance {
    return axios.create({
      baseURL: baseURL || frontendApiBase, // Set baseURL from environment variable
    })
  }

  function addInstance (serviceName: string, scopes: string): void {
    const instanceKey = getInstanceKey(serviceName, scopes)
    // Create an Axios instance with the baseURL
    const instance: AxiosInstance = createRawInstance(frontendApiBase)

    const tokenData = getTokenDataFromLocalStorage(serviceName, scopes)

    instance.interceptors.request.use(
      async (config) => {
        try {
          const savedTokenData = getSavedTokenData(serviceName, scopes)
          if (savedTokenData && savedTokenData.issuedAt && savedTokenData.expiresIn) {
            const tokenExpiresAt =
                            new Date(savedTokenData.issuedAt).getTime() + savedTokenData.expiresIn * 1000
            if (Date.now() > tokenExpiresAt) {
              // token has expired
              try {
                await refreshToken()
              } catch (refreshError) {
                logger.error(
                  `Error refreshing token for serviceName: "${serviceName}", scopes: "${scopes}":`,
                  refreshError,
                )
                await logout()
              }
            }
          }
          const token = await getToken(serviceName, scopes)
          if (token) {
            config.headers.Authorization = `Bearer ${token}`
          }

          return config
        } catch (error) {
          logger.error(
            `Error setting Authorization header for serviceName: "${serviceName}", scopes: "${scopes}":`,
            error,
          )
          // Reject the promise to prevent the request from proceeding
          return Promise.reject(
            new Error(
              `Failed to set Authorization header for serviceName: "${serviceName}", scopes: "${scopes}""`,
            ),
          )
        }
      },
      (error) => {
        // Handle request errors
        logger.error(`Request error for "${serviceName}":`, error)
        return Promise.reject(error)
      },
    )

    instance.interceptors.response.use(
      (response) => response,
      async (error: unknown) => {
        if (axios.isAxiosError(error)) {
          const originalRequest = error.config as { _retry?: boolean } & Record<string, any>

          if (error.response && error.response.status === 401 && !originalRequest?._retry) {
            originalRequest._retry = true

            try {
              await refreshToken()
              return instance(originalRequest as InternalAxiosRequestConfig)
            } catch (refreshError) {
              logger.error(
                `Error refreshing token for serviceName: "${serviceName}", scopes: "${scopes}":`,
                refreshError,
              )
              await logout()
            }
          }
        }

        if (typeof handleResponseErrors === 'function') {
          await handleResponseErrors(error as any)
        }

        return Promise.reject(error)
      },
    )

    // Add the `getWithCache` method to the instance
    instance.getWithCache = async (url: string, config = {}): Promise<AxiosResponse<any>> => {
      try {
        // 1. Check the cache first
        const cachedData = getCachedData(url)
        if (cachedData) {
          return Promise.resolve(cachedData)
        }

        // 2. Check if there's an ongoing request for the same URL
        const now = Date.now()
        const pending = pendingRequests.get(url)
        if (pending && now - pending.createdAt <= PENDING_REQUEST_TTL) {
          return pending.promise
        }

        // 3. Create the request promise and cache it
        const requestPromise = instance
          .get(url, config)
          .then((response) => {
            // @ts-ignore
            const ttl = config.cache?.ttl || 1000 * 60 * 5 // Default TTL: 5 minutes
            cacheData(url, response, ttl) // Cache the response
            pendingRequests.delete(url) // Remove from pendingRequests once done
            return response
          })
          .catch((error: unknown) => {
            pendingRequests.delete(url) // Remove from pendingRequests on error
            if (axios.isAxiosError(error) && error.response?.status === 401) {
              cache.delete(url) // Invalidate cache if unauthorized
            }
            return Promise.reject(error)
          })

        pendingRequests.set(url, { promise: requestPromise, createdAt: now }) // Store the promise in the map

        return requestPromise // Return the ongoing request promise
      } catch (error) {
        logger.error(`Error fetching with cache for URL "${url}":`, error)
        return Promise.reject(error)
      }
    }

    // Set the default Authorization header if a token exists
    if (tokenData?.accessToken) {
      instance.defaults.headers.common.Authorization = `Bearer ${tokenData.accessToken}`
    }

    instances.set(instanceKey, instance)
  }

  function getInstance (serviceName: string, scopes: string): AxiosInstance {
    const instanceKey = getInstanceKey(serviceName, scopes)
    const instance = instances.get(instanceKey)
    if (!instance) {
      throw new Error(
        `Axios instance serviceName: "${serviceName}", scopes: "${scopes}" not found.`,
      )
    }
    return instance
  }

  function getMainInstanceKey (): string {
    return getInstanceKey(mainServiceName, mainScopes)
  }

  function getInstanceKey (serviceName: string, scopes: string): string {
    return serviceName + '-' + scopes
  }

  async function logout (): Promise<void> {
    isLoggedOut = true
    refreshTokenPromise = null

    if (typeof axiosInstanceManagerConfig.beforeLogout === 'function') {
      try {
        await axiosInstanceManagerConfig.beforeLogout()
      } catch (error) {
        logger.error('Error in beforeLogout callback:', error)
        throw error
      }
    }

    const logoutServiceToken = await getToken(logoutServiceName, logoutScopes)
    if (logoutServiceToken) {
      try {
        const instanceForLogout = axios.create({
          headers: {
            Authorization: `Bearer ${logoutServiceToken}`,
          },
        })
        await instanceForLogout.delete(logoutAddress)
      } catch (error) {
        logger.error('Error during logout:', error)
        throw error
      }
    }

    clearTokens()

    // Clear credentials
    credentials.value.username = null
    credentials.value.password = null
    credentials.value.captcha = null
    credentials.value.otp = null

    cache.clear()
    pendingRequests.clear()

    if (typeof axiosInstanceManagerConfig.afterLogout === 'function') {
      try {
        await axiosInstanceManagerConfig.afterLogout()
      } catch (error) {
        logger.error('Error in afterLogout callback:', error)
        throw error
      }
    }
  }

  function clearLocalStorageKeysWithPrefix (prefix: string): void {
    if (typeof window === 'undefined') {
      return
    }
    const keysToRemove = []
    const localStorageLength = localStorage.length
    for (let i = 0; i < localStorageLength; i++) {
      const key = localStorage.key(i)
      if (key && key.startsWith(prefix)) {
        keysToRemove.push(key)
      }
    }

    keysToRemove.forEach((key) => {
      localStorage.removeItem(key)
    })
  }

  function deleteTokenMetaDataFromCookie (): void {
    if (typeof window === 'undefined') {
      return
    }
    document.cookie = `${tokenMetaDataKeyInCookie}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`
  }

  return {
    logout,
    getToken,
    addInstance,
    getInstance,
    setCredentials,
    obtainMainToken,
    getSavedTokenData,
    createRawInstance,
    verifyMainTokenMfa,
    markMainTokenMfaVerified,
    getMainTokenDataFromCookie,
    getTokenDataFromLocalStorage,
  }
}

export default function manager (axiosInstanceManagerConfig: AxiosInstanceManagerConfigType): ReturnType<typeof createInstance> {
  if (!instance) {
    instance = createInstance(axiosInstanceManagerConfig)
  }
  return instance
}
