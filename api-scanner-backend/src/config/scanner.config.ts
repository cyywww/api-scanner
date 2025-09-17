// Scanner configuration file
export const ScannerConfig = {
  xss: {
    // Maximum number of payloads to test per form field
    maxPayloadsPerField: 3,
    // Whether to check for stored XSS
    checkStoredXSS: true,
    // Delay before checking stored XSS (ms)
    storageCheckDelay: 1000,
    // Check if payload is properly encoded
    encodingCheck: true,
    // Common pages to check for stored XSS
    storedXSSPages: [
      '/guestbook',
      '/comments',
      '/messages',
      '/forum',
      '/posts',
    ],
  },
  sql: {
    // Threshold for time-based SQL injection (ms)
    timeBasedThreshold: 4000,
    // Number of baseline attempts for timing
    baselineAttempts: 3,
    // Number of test attempts per payload
    testAttempts: 2,
    // Minimum success rate to confirm vulnerability
    minSuccessRate: 0.66,
    // Delay between baseline attempts (ms)
    baselineDelay: 500,
  },
  network: {
    // Request timeout (ms)
    timeout: 10000,
    // Number of retries for failed requests
    retries: 2,
    // Delay between retries (ms)
    retryDelay: 500,
    // Maximum response size (bytes)
    maxContentLength: 50 * 1024 * 1024,
  },
  validation: {
    // Exclude payloads found in safe contexts
    excludeSafeContexts: true,
    // Check for false positives
    checkFalsePositives: true,
    // Require evidence for vulnerabilities
    requireEvidence: true,
    // Deduplicate similar results
    deduplicateResults: true,
  },
  // False positive patterns to exclude
  falsePositivePatterns: [
    /error loading page/i,
    /network error/i,
    /user error/i,
    /input error/i,
    /page not found/i,
    /404 error/i,
  ],
  // Safe contexts where XSS payloads don't execute
  safeContextPatterns: [
    /<textarea[^>]*>.*?<\/textarea>/gis,
    /<script[^>]*>.*?<\/script>/gis,
    /<!--.*?-->/gs,
    /<style[^>]*>.*?<\/style>/gis,
  ],
};
