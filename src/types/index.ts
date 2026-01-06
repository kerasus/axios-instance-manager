import type { AxiosError } from 'axios'
import type { LogLevel } from '../logger'

export interface TokenMetaDataType {
    tokenType: string | null
    expiresIn: number | null // in second
    refreshExpiresIn: number | null // in second
    otpExpiresIn?: number | null // in second
    issuedAt: number | null
    mfaEnabled?: boolean
    mfaVerified?: boolean
}

export interface TokenData extends TokenMetaDataType {
    serviceName: string | null
    scopes: string | null
    accessToken: string | null
    refreshToken: string | null
}

export interface AxiosInstanceManagerConfigType {
    mainScopes: string;
    mainServiceName: string;
    logoutScopes: string;
    logoutServiceName: string;
    frontendApiBase: string;
    tokenDataInLocalStoragePrefix: string;
    getMainTokenAddress: string;
    logoutAddress: string;
    getRefreshTokenAddress: string;
    verifyMainTokenMfaAddress: string;
    localStorageKeyPrefix: string;
    tokenMetaDataKeyInCookie: string;
    getServiceTokenAddress: (serviceName: string) => string;
    setUser?: (tokenData: TokenData, decodedToken: Record<string, any>) => Promise<void>;
    afterLogout: () => Promise<void>;
    beforeLogout: () => Promise<void>;
    handleResponseErrors: (error: AxiosError<ServiceResponseError>) => Promise<void>;
    logLevel: LogLevel;
}

export interface CacheEntry {
    data: unknown
    expiry: number
}

export interface ResponseErrorDetail {
    loc: string
    type: string
    parameters: Record<string, string | number>
    hasError?: boolean
}

export interface ServiceResponseError {
    clientError: null | string | number
    errorCode: null | string | number
    errorMessage: null | string
    errorService: null | string
    detail: ResponseErrorDetail[]
}

export interface DecodedJwtObjectType {
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
        customerId: string
    }
    signature: string
}