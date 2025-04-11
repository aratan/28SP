/**
 * Utility functions for error handling, logging, and common operations
 */

// Logging levels
const LogLevel = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug'
};

// Current log level (can be changed at runtime)
let currentLogLevel = LogLevel.INFO;

/**
 * Set the current logging level
 * @param {string} level - The log level to set
 */
function setLogLevel(level) {
  if (Object.values(LogLevel).includes(level)) {
    currentLogLevel = level;
    logInfo(`Log level set to: ${level}`);
  } else {
    logError(`Invalid log level: ${level}`);
  }
}

/**
 * Log an error message
 * @param {string} message - The error message
 * @param {Error|null} error - Optional error object
 */
function logError(message, error = null) {
  console.error(`[ERROR] ${message}`, error || '');
  // Could also send to a server-side logging endpoint
}

/**
 * Log a warning message
 * @param {string} message - The warning message
 */
function logWarning(message) {
  if ([LogLevel.WARN, LogLevel.INFO, LogLevel.DEBUG].includes(currentLogLevel)) {
    console.warn(`[WARN] ${message}`);
  }
}

/**
 * Log an info message
 * @param {string} message - The info message
 */
function logInfo(message) {
  if ([LogLevel.INFO, LogLevel.DEBUG].includes(currentLogLevel)) {
    console.info(`[INFO] ${message}`);
  }
}

/**
 * Log a debug message
 * @param {string} message - The debug message
 */
function logDebug(message) {
  if (currentLogLevel === LogLevel.DEBUG) {
    console.debug(`[DEBUG] ${message}`);
  }
}

/**
 * Display an error notification to the user
 * @param {string} message - The error message to display
 * @param {number} duration - How long to show the notification (ms)
 */
function showErrorNotification(message, duration = 5000) {
  showNotification(message, 'error', duration);
}

/**
 * Display a success notification to the user
 * @param {string} message - The success message to display
 * @param {number} duration - How long to show the notification (ms)
 */
function showSuccessNotification(message, duration = 3000) {
  showNotification(message, 'success', duration);
}

/**
 * Display an info notification to the user
 * @param {string} message - The info message to display
 * @param {number} duration - How long to show the notification (ms)
 */
function showInfoNotification(message, duration = 3000) {
  showNotification(message, 'info', duration);
}

/**
 * Generic notification function
 * @param {string} message - The message to display
 * @param {string} type - The type of notification (error, success, info)
 * @param {number} duration - How long to show the notification (ms)
 */
function showNotification(message, type = 'info', duration = 3000) {
  // Check if notification container exists, create if not
  let notificationContainer = document.getElementById('notification-container');
  
  if (!notificationContainer) {
    notificationContainer = document.createElement('div');
    notificationContainer.id = 'notification-container';
    notificationContainer.style.position = 'fixed';
    notificationContainer.style.top = '20px';
    notificationContainer.style.right = '20px';
    notificationContainer.style.zIndex = '9999';
    document.body.appendChild(notificationContainer);
  }
  
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.innerHTML = `
    <div class="notification-content">
      <span class="notification-message">${message}</span>
      <button class="notification-close">&times;</button>
    </div>
  `;
  
  // Style the notification
  notification.style.backgroundColor = type === 'error' ? '#f8d7da' : 
                                      type === 'success' ? '#d4edda' : '#d1ecf1';
  notification.style.color = type === 'error' ? '#721c24' : 
                            type === 'success' ? '#155724' : '#0c5460';
  notification.style.padding = '10px 15px';
  notification.style.marginBottom = '10px';
  notification.style.borderRadius = '4px';
  notification.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
  notification.style.transition = 'all 0.3s ease';
  
  // Add close button functionality
  const closeButton = notification.querySelector('.notification-close');
  closeButton.style.background = 'none';
  closeButton.style.border = 'none';
  closeButton.style.float = 'right';
  closeButton.style.cursor = 'pointer';
  closeButton.style.fontSize = '20px';
  closeButton.style.marginLeft = '10px';
  
  closeButton.addEventListener('click', () => {
    notification.style.opacity = '0';
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  });
  
  // Add to container
  notificationContainer.appendChild(notification);
  
  // Auto-remove after duration
  setTimeout(() => {
    notification.style.opacity = '0';
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  }, duration);
}

/**
 * Safe fetch wrapper with error handling
 * @param {string} url - The URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise} - The fetch promise
 */
async function safeFetch(url, options = {}) {
  try {
    logDebug(`Fetching: ${url}`);
    const response = await fetch(url, options);
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP error ${response.status}: ${errorText}`);
    }
    
    // Try to parse as JSON, fall back to text if not valid JSON
    try {
      const text = await response.text();
      if (!text || text.trim() === '') {
        return null;
      }
      return JSON.parse(text);
    } catch (parseError) {
      logWarning(`Response is not valid JSON: ${parseError.message}`);
      // Return the raw text if JSON parsing fails
      return await response.text();
    }
  } catch (error) {
    logError(`Fetch error for ${url}:`, error);
    throw error;
  }
}

/**
 * Debounce function to limit how often a function can be called
 * @param {Function} func - The function to debounce
 * @param {number} wait - The debounce wait time in ms
 * @returns {Function} - The debounced function
 */
function debounce(func, wait = 300) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Throttle function to limit how often a function can be called
 * @param {Function} func - The function to throttle
 * @param {number} limit - The throttle limit time in ms
 * @returns {Function} - The throttled function
 */
function throttle(func, limit = 300) {
  let inThrottle;
  return function executedFunction(...args) {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => {
        inThrottle = false;
      }, limit);
    }
  };
}

// Export all functions
export {
  LogLevel,
  setLogLevel,
  logError,
  logWarning,
  logInfo,
  logDebug,
  showErrorNotification,
  showSuccessNotification,
  showInfoNotification,
  safeFetch,
  debounce,
  throttle
};
