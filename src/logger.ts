export type LogLevel = 'none' | 'error' | 'warn' | 'info' | 'debug'

export interface Logger {
  error: (message: string, ...optionalParams: unknown[]) => void;
  warn: (message: string, ...optionalParams: unknown[]) => void;
  info: (message: string, ...optionalParams: unknown[]) => void;
  debug: (message: string, ...optionalParams: unknown[]) => void;
}

export function createLogger (level: LogLevel): Logger {
  const levels: Record<LogLevel, number> = {
    none: 0,
    error: 1,
    warn: 2,
    info: 3,
    debug: 4,
  }

  const currentLevel = levels[level] ?? 0
  
  return {
    error: (message: string, ...optionalParams: unknown[]): void => {
      if (currentLevel >= 1 && typeof console !== 'undefined') {
        console.error(`[AuthManager ERROR] ${message}`, ...optionalParams)
      }
    },
    warn: (message: string, ...optionalParams: unknown[]): void => {
      if (currentLevel >= 2 && typeof console !== 'undefined') {
        console.warn(`[AuthManager WARN] ${message}`, ...optionalParams)
      }
    },
    info: (message: string, ...optionalParams: unknown[]): void => {
      if (currentLevel >= 3 && typeof console !== 'undefined') {
        console.info(`[AuthManager INFO] ${message}`, ...optionalParams)
      }
    },
    debug: (message: string, ...optionalParams: unknown[]): void => {
      if (currentLevel >= 4 && typeof console !== 'undefined') {
        console.debug(`[AuthManager DEBUG] ${message}`, ...optionalParams)
      }
    },
  }
}
