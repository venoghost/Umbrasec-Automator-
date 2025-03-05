type ErrorLogLevel = "info" | "warn" | "error"

export function logError(error: Error, level: ErrorLogLevel = "error") {
  // In a real application, you might want to send this to a logging service
  console[level](`[${new Date().toISOString()}] ${level.toUpperCase()}: ${error.message}`)
  console[level](error.stack)

  // You could also implement sending logs to a service like Sentry here
}

