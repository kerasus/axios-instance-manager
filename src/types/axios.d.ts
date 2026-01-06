import type {
  AxiosError as OriginalAxiosError,
  AxiosInstance as OriginalAxiosInstance,
  AxiosResponse as OriginalAxiosResponse,
  AxiosRequestConfig as OriginalAxiosRequestConfig,
  AxiosResponse,
} from 'axios'

export type ApiErrorDetailItemType = {
  loc: string | null
  type: string | null
  parameters: {
    type: string | null
    value: string | null
  }
}

export type ApiErrorType = {
  detail: ApiErrorDetailItemType[]
  errorMessage: string
  errorCode: number | string | null
  errorService: string | null
  clientError: string | null
}

declare module 'axios' {
  interface AxiosRequestConfig extends OriginalAxiosRequestConfig {
    useCache?: boolean
    cache?: {
      ttl?: number
    }
  }

  // Extend AxiosInstance to include getWithCache
  interface AxiosInstance extends OriginalAxiosInstance {
    getWithCache(url: string, config?: AxiosRequestConfig): Promise<OriginalAxiosResponse>
  }

  interface AxiosError<T = ApiErrorType, D = any> extends OriginalAxiosError {
    response?: AxiosResponse<T, D>
  }
}
