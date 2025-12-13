export type LogLevel = 'none' | 'error' | 'warn' | 'info' | 'debug'

export function createLogger (level: LogLevel) {
  const levels: Record<LogLevel, number> = {
    none: 0,
    error: 1,
    warn: 2,
    info: 3,
    debug: 4
  }

  const currentLevel = levels[level] ?? 0
  
  return {
    error: (message: string, ...optionalParams: any[]) => {
      if (currentLevel >= 1 && typeof console !== 'undefined') {
        console.error(`[AuthManager ERROR] ${message}`, ...optionalParams)
      }
    },
    warn: (message: string, ...optionalParams: any[]) => {
      if (currentLevel >= 2 && typeof console !== 'undefined') {
        console.warn(`[AuthManager WARN] ${message}`, ...optionalParams)
      }
    },
    info: (message: string, ...optionalParams: any[]) => {
      if (currentLevel >= 3 && typeof console !== 'undefined') {
        console.info(`[AuthManager INFO] ${message}`, ...optionalParams)
      }
    },
    debug: (message: string, ...optionalParams: any[]) => {
      if (currentLevel >= 4 && typeof console !== 'undefined') {
        console.debug(`[AuthManager DEBUG] ${message}`, ...optionalParams)
      }
    }
  }
}
