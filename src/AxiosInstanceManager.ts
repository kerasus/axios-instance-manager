import { ref } from 'vue'
import type { AxiosError, AxiosInstance, AxiosResponse } from 'axios'
import axios from 'axios'
import { getDecodeJwt } from './jwtUtils'

export interface TokenMetaDataType {
    tokenType: string | null
    expiresIn: number | null
    refreshExpiresIn: number | null
    issuedAt: number | null
}

interface TokenData extends TokenMetaDataType {
    serviceName: string | null
    scopes: string | null
    accessToken: string | null
    refreshToken: string | null
}

interface AxiosInstanceManagerConfigType {
    mainScopes: string;
    mainServiceName: string;
    frontendApiBase: string;
    tokenDataInLoacalStoragePrefix: string;
    getMainTokenAddress: string;
    getRefreshTokenAddress: string;
    serverMessagesPrefix: string;
    localStorageKeyPrefix: string;
    tokenMetaDataKeyInCookie: string;
    getServiceTokenAddress: (serviceName: string) => string;
    setUser: (decodedToken: Record<string, any>) => void;
    goToLoginPage: () => void;

}

let instance: ReturnType<typeof createInstance> | null = null

interface CacheEntry {
    data: any
    expiry: number
}

export interface ResponseErrorDetail {
    loc: string
    type: string
    hasError?: boolean
}

const cache = new Map<string, CacheEntry>()
const pendingRequests = new Map<string, Promise<AxiosResponse | AxiosError>>()

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
                config: {}
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
        expiry: Date.now() + ttl
    })
}

function createInstance (axiosInstanceManagerConfig: AxiosInstanceManagerConfigType) {
    const mainScopes = axiosInstanceManagerConfig.mainScopes
    const mainServiceName = axiosInstanceManagerConfig.mainServiceName
    const frontendApiBase = axiosInstanceManagerConfig.frontendApiBase
    const tokenDataInLoacalStoragePrefix = axiosInstanceManagerConfig.tokenDataInLoacalStoragePrefix
    const getMainTokenAddress = axiosInstanceManagerConfig.getMainTokenAddress
    const getRefreshTokenAddress = axiosInstanceManagerConfig.getRefreshTokenAddress
    const getServiceTokenAddress = axiosInstanceManagerConfig.getServiceTokenAddress

    const instances = ref<Record<string, AxiosInstance>>({})
    const tokens = ref<Record<string, TokenData | null>>({})
    const credentials = ref<{
        username: string | null
        password: string | null
        captcha: string | null
    }>({
        username: null,
        password: null,
        captcha: null
    })
    let refreshTokenPromise: Promise<void> | null = null

    const mainInstanceKey = getMainInstanceKey()
    tokens.value[mainInstanceKey] = loadTokenData(mainServiceName, mainScopes)

    function getLocalStorageKey (serviceName: string, scopes: string) {
        const instanceKey = getInstanceKey(serviceName, scopes)

        return `${axiosInstanceManagerConfig.localStorageKeyPrefix}_${tokenDataInLoacalStoragePrefix}${instanceKey}`
    }

    function saveTokenData (serviceName: string, scopes: string, tokenData: TokenData): void {
        const mainInstanceKey = getMainInstanceKey()
        const instanceKey = getInstanceKey(serviceName, scopes)
        const localStorageKey = getLocalStorageKey(serviceName, scopes)
        if (typeof window === 'undefined') {
            return
        }
        localStorage.setItem(localStorageKey, JSON.stringify(tokenData))
        if (mainInstanceKey === instanceKey) {
            saveTokenDataToCookie({
                tokenType: tokenData.tokenType,
                expiresIn: tokenData.expiresIn,
                refreshExpiresIn: tokenData.refreshExpiresIn,
                issuedAt: tokenData.issuedAt
            })
        }
    }

    function loadTokenData (serviceName: string, scopes: string): TokenData | null {
        const localStorageKey = getLocalStorageKey(serviceName, scopes)
        if (typeof window === 'undefined') {
            return null
        }
        const data = localStorage.getItem(localStorageKey)
        return data
            ? JSON.parse(data)
            : {
                serviceName: null,
                scopes: null,
                tokenType: null,
                accessToken: null,
                refreshToken: null,
                issuedAt: null,
                expiresIn: null,
                refreshExpiresIn: null
            }
    }

    function setCredentials (username: string, password: string, captcha: string): void {
        credentials.value.username = username
        credentials.value.password = password
        credentials.value.captcha = captcha
    }

    function getSavedTokenData (serviceName: string, scopes: string): TokenData | null {
        const instanceKey = getInstanceKey(serviceName, scopes)
        tokens.value[instanceKey] = loadTokenData(serviceName, scopes)
        return tokens.value[instanceKey]
    }

    async function getToken (serviceName: string, scopes: string): Promise<string | null | undefined> {
        const mainInstanceKey = getMainInstanceKey()
        const instanceKey = getInstanceKey(serviceName, scopes)
        let tokenData = getSavedTokenData(serviceName, scopes)

        if (!tokenData?.accessToken && instanceKey === mainInstanceKey) {
            goToLoginPage()
            throw new Error('Failed to obtain main token')
        }

        try {
            if (!tokenData?.accessToken) {
                tokenData = await obtainServiceToken(serviceName, scopes)
                tokens.value[instanceKey] = tokenData
                saveTokenData(serviceName, scopes, tokenData)
                return tokenData.accessToken
            }
            return tokenData.accessToken
        } catch (error) {
            goToLoginPage()
            if (error instanceof Error) {
                console.error(
                    `Error getting token for serviceName: "${serviceName}", scopes: "${scopes}":`,
                    error
                )
                throw new Error(
                    `Failed to get token for serviceName: "${serviceName}, scopes: "${scopes}": ${error.message}`
                )
            } else {
                console.error('Unexpected error type:', error)
                throw new Error(
                    `Failed to get token for serviceName: "${serviceName}, scopes: "${scopes}"": Unexpected error`
                )
            }
        }
    }

    function saveTokenDataToCookie (tokenMetaData: TokenMetaDataType) {
        const tokenMetaDataString = JSON.stringify(tokenMetaData)

        // Set the cookie with the token data
        document.cookie = `${axiosInstanceManagerConfig.tokenMetaDataKeyInCookie}=${encodeURIComponent(tokenMetaDataString)}; path=/; SameSite=Strict;`

        // // Optionally, set an expiration date for the cookie
        // const expires = new Date()
        // expires.setTime(expires.getTime() + (tokenData.refreshExpiresIn * 1000)) // assuming refreshExpiresIn is in seconds
        // document.cookie = `tokenData=${encodeURIComponent(tokenDataString)}; path=/; expires=${expires.toUTCString()}; SameSite=Strict;`
    }

    function getMainTokenDataFromCookie (): {
        tokenType: string
        expiresIn: number
        refreshExpiresIn: number
    } | null {
        const name = 'tokenData='
        const decodedCookie = decodeURIComponent(document.cookie)
        const cookieArr = decodedCookie.split(';')

        for (let i = 0; i < cookieArr.length; i++) {
            const cookie = cookieArr[i].trim()
            if (cookie.indexOf(name) === 0) {
                const cookieValue = cookie.substring(name.length, cookie.length)
                return JSON.parse(cookieValue)
            }
        }

        return null
    }

    function getObtainServiceTokenPayload (token: string) {
        return { accessToken: token }
    }

    async function obtainMainToken (): Promise<TokenData> {
        if (!credentials.value.username || !credentials.value.password || !credentials.value.captcha) {
            throw new Error('Credentials or captcha are not set')
        }

        try {
            const response = await axios.post(getMainTokenAddress, {
                username: credentials.value.username,
                password: credentials.value.password,
                captcha: credentials.value.captcha
            })
            const data = {
                serviceName: mainServiceName,
                scopes: mainScopes,
                accessToken: response.data.accessToken,
                refreshToken: response.data.refreshToken,
                tokenType: response.data.tokenType,
                expiresIn: response.data.expiresIn,
                refreshExpiresIn: response.data.refreshExpiresIn,
                issuedAt: Date.now()
            }
            const mainInstanceKey = getMainInstanceKey()
            tokens.value[mainInstanceKey] = data
            saveTokenData(mainServiceName, mainScopes, data)

            // Save token data to cookie and use that in
            // Authenticated middleware for ssr mode
            saveTokenDataToCookie({
                tokenType: response.data.tokenType,
                expiresIn: response.data.expiresIn,
                refreshExpiresIn: response.data.refreshExpiresIn,
                issuedAt: Date.now()
            })
            await setAuthenticatedUserData()

            return data
        } catch (error) {
            console.error('Error obtaining main token:', error)
            // Explicitly reject the promise by throwing an error
            throw new Error('Failed to obtain main token')
        }
    }

    async function obtainServiceToken (serviceName: string, scopes: string): Promise<TokenData> {
        try {
            let mainToken = await getToken(mainServiceName, mainScopes)
            if (!mainToken) {
                throw new Error('Main token not available')
            }

            const instanceForObtainServiceToken = axios.create({
                baseURL: frontendApiBase // Set baseURL from environment variable
            })

            instanceForObtainServiceToken.interceptors.response.use(
                (response) => response,
                async (error) => {
                    const originalRequest = error.config
                    if (error.response && error.response.status === 401 && !originalRequest._retry) {
                        originalRequest._retry = true

                        try {
                            await refreshToken()
                            mainToken = await getToken(mainServiceName, mainScopes)
                            if (mainToken) {
                                originalRequest.data = JSON.stringify(getObtainServiceTokenPayload(mainToken))
                                return instanceForObtainServiceToken(originalRequest)
                            }
                        } catch (refreshError) {
                            console.error(`Error refreshing token for "${serviceName}":`, refreshError)
                            return Promise.reject(refreshError)
                        }
                    }
                    return Promise.reject(error)
                }
            )

            const response = await instanceForObtainServiceToken.put(
                getServiceTokenAddress(serviceName),
                getObtainServiceTokenPayload(mainToken),
                {
                    params: { scopes }
                }
            )

            const tokenData = {
                serviceName,
                scopes,
                accessToken: response.data.accessToken,
                refreshToken: response.data.refreshToken,
                tokenType: response.data.tokenType,
                expiresIn: response.data.expiresIn,
                refreshExpiresIn: response.data.refreshExpiresIn,
                issuedAt: Date.now()
            }
            saveTokenData(serviceName, scopes, tokenData)
            return tokenData
        } catch (error) {
            console.error(
                `Error obtaining token for serviceName: "${serviceName}", scopes: "${scopes}":`,
                error
            )
            throw new Error(`Failed to obtain serviceName: "${serviceName}", scopes: "${scopes}" token`)
        }
    }

    function clearTokens (): void {
        Object.keys(tokens.value).forEach((instanceKey) => {
            if (tokens.value[instanceKey]) {
                tokens.value[instanceKey].accessToken = null
                tokens.value[instanceKey].expiresIn = null
                tokens.value[instanceKey].refreshToken = null
                tokens.value[instanceKey].refreshExpiresIn = null
                tokens.value[instanceKey].issuedAt = null
            }
        })
        saveTokenDataToCookie({
            tokenType: null,
            expiresIn: null,
            refreshExpiresIn: null,
            issuedAt: null
        })
    }

    async function setAuthenticatedUserData () {
        const token = await getToken(mainServiceName, mainScopes)
        if (token) {
            const decodedToken = getDecodeJwt(token)
            if (decodedToken) {
                axiosInstanceManagerConfig.setUser(decodedToken)
            }
        }
    }

    async function refreshToken (): Promise<void> {
        if (refreshTokenPromise) {
            return refreshTokenPromise
        }

        refreshTokenPromise = (async () => {
            try {
                const mainInstanceKey = getMainInstanceKey()
                const mainTokenData = tokens.value[mainInstanceKey]

                if (!mainTokenData || !mainTokenData.refreshToken) {
                    throw new Error(`No refresh token available for MainService: "${mainServiceName}"`)
                }

                // Send POST request to the refresh-token endpoint and refresh main token
                const response = await axios.put(getRefreshTokenAddress, {
                    refreshToken: mainTokenData.refreshToken // Use refreshToken as the key
                })
                clearTokens()

                // Update main token with the new access token and refresh token
                tokens.value[mainInstanceKey] = {
                    serviceName: mainServiceName,
                    scopes: mainScopes,
                    accessToken: response.data.accessToken,
                    refreshToken: response.data.refreshToken,
                    tokenType: response.data.tokenType,
                    expiresIn: response.data.expiresIn,
                    refreshExpiresIn: response.data.refreshExpiresIn,
                    issuedAt: Date.now()
                }

                // Save the new tokens in local storage
                saveAllTokensData()
                await setAuthenticatedUserData()
            } catch (error) {
                console.error('Error refreshing token', error)
                throw new Error('Error refreshing token: Unexpected error')
            } finally {
                refreshTokenPromise = null
            }
        })()

        return refreshTokenPromise
    }

    function saveAllTokensData () {
        Object.keys(tokens.value).forEach((instanceKey) => {
            const tokenItem = tokens.value[instanceKey]
            const serviceName = tokenItem?.serviceName
            const scopes = tokenItem?.scopes
            if (serviceName && scopes && tokens.value[instanceKey]) {
                saveTokenData(serviceName, scopes, tokens.value[instanceKey])
            }
        })
    }

    function addInstance (serviceName: string, scopes: string): void {
        const instanceKey = getInstanceKey(serviceName, scopes)
        // Create an Axios instance with the baseURL
        const instance: AxiosInstance = axios.create({
            baseURL: frontendApiBase // Set baseURL from environment variable
        })

        const tokenData = loadTokenData(serviceName, scopes)

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
                                console.error(
                                    `Error refreshing token for serviceName: "${serviceName}", scopes: "${scopes}":`,
                                    refreshError
                                )
                                goToLoginPage()
                            }
                        }
                    }
                    const token = await getToken(serviceName, scopes)
                    if (token) {
                        config.headers.Authorization = `Bearer ${token}`
                    }

                    return config
                } catch (error) {
                    console.error(
                        `Error setting Authorization header for serviceName: "${serviceName}", scopes: "${scopes}":`,
                        error
                    )
                    // Reject the promise to prevent the request from proceeding
                    return Promise.reject(
                        new Error(
                            `Failed to set Authorization header for serviceName: "${serviceName}", scopes: "${scopes}""`
                        )
                    )
                }
            },
            (error) => {
                // Handle request errors
                console.error(`Request error for "${serviceName}":`, error)
                return Promise.reject(error)
            }
        )

        instance.interceptors.response.use(
            (response) => response,
            async (error) => {
                const originalRequest = error.config

                if (error.response && error.response.status === 401 && !originalRequest._retry) {
                    originalRequest._retry = true

                    try {
                        await refreshToken()
                        return instance(originalRequest)
                    } catch (refreshError) {
                        console.error(
                            `Error refreshing token for serviceName: "${serviceName}", scopes: "${scopes}":`,
                            refreshError
                        )
                        goToLoginPage()
                    }
                }

                if (error.response) {
                    const { detail } = error.response.data
                    if (Array.isArray(detail) && detail.length > 0) {
                        notifyError(
                            (detail as ResponseErrorDetail[]).map((item) => {
                                return {
                                    loc: item.loc,
                                    type: `${axiosInstanceManagerConfig.serverMessagesPrefix}.${item.type}`
                                }
                            })
                        )
                    } else if (Array.isArray(detail) && detail.length === 0) {
                        notifyError('error.' + error.response.status)
                    } else {
                        notifyError('unknownError')
                    }
                } else {
                    notifyError('error.0')
                }

                return Promise.reject(error)
            }
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
                if (pendingRequests.has(url)) {
                    return pendingRequests.get(url) as Promise<AxiosResponse<any>>
                }

                // 3. Create the request promise and cache it
                const requestPromise = instance
                    .get(url, config)
                    .then((response) => {
                        const ttl = config.cache?.ttl || 1000 * 60 * 5 // Default TTL: 5 minutes
                        cacheData(url, response, ttl) // Cache the response
                        pendingRequests.delete(url) // Remove from pendingRequests once done
                        return response
                    })
                    .catch((error) => {
                        pendingRequests.delete(url) // Remove from pendingRequests on error
                        return Promise.reject(error)
                    })

                pendingRequests.set(url, requestPromise) // Store the promise in the map

                return requestPromise // Return the ongoing request promise
            } catch (error) {
                console.error(`Error fetching with cache for URL "${url}":`, error)
                return Promise.reject(error)
            }
        }

        // Set the default Authorization header if a token exists
        if (tokenData?.accessToken) {
            instance.defaults.headers.common.Authorization = `Bearer ${tokenData.accessToken}`
        }

        instances.value[instanceKey] = instance
    }

    function getInstance (serviceName: string, scopes: string): AxiosInstance {
        const instanceKey = getInstanceKey(serviceName, scopes)
        const instance = instances.value[instanceKey]
        if (!instance) {
            throw new Error(
                `Axios instance serviceName: "${serviceName}", scopes: "${scopes}" not found.`
            )
        }
        return instance
    }

    function getMainInstanceKey () {
        return getInstanceKey(mainServiceName, mainScopes)
    }

    function getInstanceKey (serviceName: string, scopes: string) {
        return serviceName + '-' + scopes
    }

    function logout (): void {
        // Clear all tokens
        for (const serviceName in tokens.value) {
            tokens.value[serviceName] = null
        }

        if (typeof window !== 'undefined') {
            sessionStorage.clear()
            localStorage.clear()
            deleteAllCookies()
        }

        // Clear credentials
        credentials.value.username = null
        credentials.value.password = null
    }

    function deleteAllCookies () {
        if (typeof window === 'undefined') {
            return
        }
        const cookies = document.cookie.split(';')

        for (const cookie of cookies) {
            const eqPos = cookie.indexOf('=')
            const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie
            document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`
        }
    }

    function goToLoginPage () {
        axiosInstanceManagerConfig.goToLoginPage()
    }

    function notifyError (message: string | ResponseErrorDetail[]) {
        // Create a new custom event
        const customEvent = new CustomEvent('axios-interceptors-response-error', {
            detail: { message }
        })
        // Dispatch the event on any DOM element
        window.dispatchEvent(customEvent)
    }

    return {
        logout,
        getToken,
        addInstance,
        getInstance,
        loadTokenData,
        setCredentials,
        obtainMainToken,
        getSavedTokenData,
        getMainTokenDataFromCookie
    }
}

export default function AxiosInstanceManager (axiosInstanceManagerConfig: AxiosInstanceManagerConfigType) {
    if (!instance) {
        instance = createInstance(axiosInstanceManagerConfig)
    }
    return instance
}
