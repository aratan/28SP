// Enhanced main JavaScript for P2P Secure Messenger
import {
  logError,
  logWarning,
  logInfo,
  logDebug,
  showErrorNotification,
  showSuccessNotification,
  showInfoNotification,
  safeFetch,
  debounce,
  throttle,
} from "./utils.js";

// Global variables
let token = localStorage.getItem("token");
let filteredTablones = [];
let currentPage = 1;
const itemsPerPage = 5;
let lastFetchedData = null;
let refreshStatus = {
  isRefreshing: false,
  autoRefreshEnabled: true,
  refreshIntervalId: null,
  currentRefreshInterval: 30000,
  lastRefreshTime: null,
};
let selectedFile = null;

// Theme management
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.className = `${savedTheme}-theme`;
  updateThemeToggleIcon(savedTheme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.classList.contains('dark-theme') ? 'dark' : 'light';
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  
  document.documentElement.className = `${newTheme}-theme`;
  localStorage.setItem('theme', newTheme);
  updateThemeToggleIcon(newTheme);
}

function updateThemeToggleIcon(theme) {
  const themeToggle = document.getElementById('themeToggle');
  const icon = themeToggle.querySelector('i');
  icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
}

// Security status management
function updateSecurityStatus() {
  const encryptionIndicator = document.getElementById('encryptionIndicator');
  const anonymityIndicator = document.getElementById('anonymityIndicator');
  const routingIndicator = document.getElementById('routingIndicator');
  const securityStatusText = document.getElementById('securityStatusText');
  
  const encryptMessages = document.getElementById('encryptMessages').checked;
  const anonymousMode = document.getElementById('anonymousMode').checked;
  const onionRouting = document.getElementById('onionRouting').checked;
  
  // Update indicators
  encryptionIndicator.className = encryptMessages ? 'security-indicator active' : 'security-indicator inactive';
  anonymityIndicator.className = anonymousMode ? 'security-indicator active' : 'security-indicator inactive';
  routingIndicator.className = onionRouting ? 'security-indicator active' : 'security-indicator inactive';
  
  // Update status text
  let statusText = 'Conectado';
  if (encryptMessages) statusText += ' • Cifrado E2E';
  if (anonymousMode) statusText += ' • Anónimo';
  if (onionRouting) statusText += ' • Enrutamiento Cebolla';
  
  securityStatusText.textContent = statusText;
  
  // Show/hide security status bar
  const statusBar = document.getElementById('securityStatusBar');
  if (encryptMessages || anonymousMode || onionRouting) {
    statusBar.classList.remove('d-none');
  } else {
    statusBar.classList.add('d-none');
  }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
  initTheme();
  
  // Theme toggle
  document.getElementById('themeToggle').addEventListener('click', toggleTheme);
  
  // Check if user is already logged in
  if (token) {
    showApp();
    refreshTablones();
  } else {
    showLogin();
  }
  
  // Set up event listeners
  setupEventListeners();
  
  // Start auto-refresh
  startAutoRefresh();
  
  // Initialize security status
  updateSecurityStatus();
});

// Set up event listeners
function setupEventListeners() {
  // Login form
  document.getElementById('loginFormElement').addEventListener('submit', handleLogin);
  
  // Logout button
  document.getElementById('logoutBtn').addEventListener('click', handleLogout);
  
  // Create tablón button
  document.getElementById('createTablonBtn').addEventListener('click', () => {
    new bootstrap.Modal(document.getElementById('createTablonModal')).show();
  });
  
  // Create tablón form
  document.getElementById('createTablonForm').addEventListener('submit', handleCreateTablon);
  
  // Refresh button
  document.getElementById('refreshBtn').addEventListener('click', refreshTablones);
  
  // Security settings
  document.getElementById('anonymousMode').addEventListener('change', function() {
    updateSecuritySettings();
    updateSecurityStatus();
  });
  document.getElementById('encryptMessages').addEventListener('change', function() {
    updateSecuritySettings();
    updateSecurityStatus();
  });
  document.getElementById('onionRouting').addEventListener('change', function() {
    updateSecuritySettings();
    updateSecurityStatus();
  });
  
  // Client-side encryption controls
  document.getElementById('generateKeyBtn').addEventListener('click', generateEncryptionKey);
  document.getElementById('exportKeyBtn').addEventListener('click', exportEncryptionKey);
  document.getElementById('importKeyBtn').addEventListener('click', () => {
    document.getElementById('keyFileInput').click();
  });
  document.getElementById('keyFileInput').addEventListener('change', importEncryptionKey);
  
  // File transfer controls
  document.getElementById('sendFileBtn').addEventListener('click', () => {
    document.getElementById('fileInput').click();
  });
  document.getElementById('fileInput').addEventListener('change', handleFileSelection);
  document.getElementById('sendFileForm').addEventListener('submit', handleSendFile);
}

// Handle login
async function handleLogin(e) {
  e.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const peerId = document.getElementById('peerId').value;
  
  try {
    logInfo(`Attempting login with username: ${username}`);
    
    // Show loading state
    const loginButton = document.querySelector('#loginFormElement button[type="submit"]');
    const originalText = loginButton.innerHTML;
    loginButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando sesión...';
    loginButton.disabled = true;
    
    const response = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, peerId, photo: "" }),
    });
    
    if (response.ok) {
      const data = await response.json();
      token = data.token;
      localStorage.setItem("token", token);
      showSuccessNotification("Sesión iniciada correctamente");
      logInfo("Login successful");
      showApp();
      refreshTablones();
    } else {
      const errorText = await response.text();
      logError(`Login error: ${response.status} - ${errorText}`);
      showErrorNotification("Credenciales inválidas");
    }
  } catch (error) {
    logError("Error during login:", error);
    showErrorNotification(`Error de conexión: ${error.message}`);
  } finally {
    // Restore button
    const loginButton = document.querySelector('#loginFormElement button[type="submit"]');
    loginButton.innerHTML = '<i class="fas fa-sign-in-alt me-2"></i>Iniciar Sesión';
    loginButton.disabled = false;
  }
}

// Handle logout
function handleLogout() {
  token = null;
  localStorage.removeItem("token");
  showLogin();
  showInfoNotification("Sesión cerrada correctamente");
}

// Show login screen
function showLogin() {
  document.getElementById('loginSection').classList.remove('d-none');
  document.getElementById('appSection').classList.add('d-none');
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('peerId').value = '';
}

// Show main app
function showApp() {
  document.getElementById('loginSection').classList.add('d-none');
  document.getElementById('appSection').classList.remove('d-none');
}

// Handle create tablón
async function handleCreateTablon(e) {
  e.preventDefault();
  
  const name = document.getElementById('tablonName').value;
  const message = document.getElementById('tablonMessage').value;
  const geo = document.getElementById('tablonGeo').value;
  
  try {
    if (!token) {
      throw new Error("No hay token disponible. Inicia sesión primero.");
    }
    
    logInfo(`Creating tablón: ${name}`);
    
    const url = `/api/createTablon?name=${encodeURIComponent(name)}&mensaje=${encodeURIComponent(message)}&geo=${encodeURIComponent(geo)}`;
    
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": token,
      },
    });
    
    if (response.ok) {
      showSuccessNotification("Tablón creado correctamente");
      logInfo("Tablón created successfully");
      
      // Close modal and reset form
      bootstrap.Modal.getInstance(document.getElementById('createTablonModal')).hide();
      document.getElementById('createTablonForm').reset();
      
      // Refresh tablones
      refreshTablones();
    } else {
      throw new Error(`Error ${response.status}: ${await response.text()}`);
    }
  } catch (error) {
    logError("Error creating tablón:", error);
    showErrorNotification(`Error al crear el tablón: ${error.message}`);
  }
}

// Refresh tablones
async function refreshTablones() {
  if (refreshStatus.isRefreshing) return;
  
  try {
    refreshStatus.isRefreshing = true;
    logDebug("Refreshing tablones");
    
    const data = await safeFetch("/api/readTablon");
    const tablones = Array.isArray(data) ? data : [];
    
    // Only update if data has changed
    if (JSON.stringify(tablones) !== JSON.stringify(lastFetchedData)) {
      lastFetchedData = tablones;
      displayTablones(tablones);
      refreshStatus.lastRefreshTime = new Date();
    }
  } catch (error) {
    logError("Error refreshing tablones:", error);
    showErrorNotification(`Error al cargar tablones: ${error.message}`);
  } finally {
    refreshStatus.isRefreshing = false;
  }
}

// Display tablones
function displayTablones(tablones) {
  filteredTablones = tablones;
  
  // Calculate pagination
  const totalPages = Math.ceil(tablones.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentTablones = tablones.slice(startIndex, endIndex);
  
  // Display tablones
  const container = document.getElementById('tablonesContainer');
  
  if (currentTablones.length === 0) {
    container.innerHTML = `
      <div class="text-center py-5">
        <i class="fas fa-inbox fa-3x mb-3" style="color: var(--gray-400);"></i>
        <p>No hay tablones disponibles</p>
        <button id="createFirstTablon" class="btn btn-primary mt-3">
          <i class="fas fa-plus me-2"></i>Crear tu primer tablón
        </button>
      </div>
    `;
    document.getElementById('createFirstTablon').addEventListener('click', () => {
      new bootstrap.Modal(document.getElementById('createTablonModal')).show();
    });
    return;
  }
  
  let html = '';
  currentTablones.forEach(tablon => {
    html += createTablonCard(tablon);
  });
  
  container.innerHTML = html;
  
  // Add event listeners to the new elements
  currentTablones.forEach(tablon => {
    // Add message form submit listener
    const form = document.getElementById(`messageForm-${tablon.ID}`);
    if (form) {
      form.addEventListener('submit', (e) => handleMessageSubmit(e, tablon.ID));
    }
    
    // Add delete tablón listener
    const deleteBtn = document.getElementById(`deleteTablon-${tablon.ID}`);
    if (deleteBtn) {
      deleteBtn.addEventListener('click', () => deleteTablon(tablon.ID));
    }
  });
  
  // Update file tablón selector
  updateFileTablonSelector(tablones);
  
  // Render pagination
  renderPagination(totalPages);
}

// Create tablón card HTML
function createTablonCard(tablon) {
  return `
    <div class="card mb-4">
      <div class="card-body">
        <div class="d-flex justify-content-between align-items-start">
          <div>
            <h4 class="card-title mb-1">${escapeHtml(tablon.Name)}</h4>
            ${tablon.Geo ? `<small class="text-muted"><i class="fas fa-map-marker-alt me-1"></i>${escapeHtml(tablon.Geo)}</small>` : ''}
          </div>
          <button id="deleteTablon-${tablon.ID}" class="btn btn-outline-danger btn-sm" title="Eliminar tablón">
            <i class="fas fa-trash"></i>
          </button>
        </div>
        
        <div class="mb-3">
          <form id="messageForm-${tablon.ID}">
            <div class="input-group">
              <input type="text" class="form-control" placeholder="Escribe un mensaje..." required>
              <button class="btn btn-primary" type="submit">
                <i class="fas fa-paper-plane"></i>
              </button>
            </div>
          </form>
        </div>
        
        <div class="messages-container">
          ${tablon.Messages && tablon.Messages.length > 0 ? 
            tablon.Messages.map(msg => createMessageElement(msg)).join('') :
            '<p class="text-muted text-center py-3">No hay mensajes aún</p>'
          }
        </div>
      </div>
    </div>
  `;
}

// Create message element HTML
function createMessageElement(message) {
  // Check if this is a file message
  const isFileMessage = message.FileName && message.BinaryData;
  
  if (isFileMessage) {
    return `
      <div class="border-bottom border-gray-200 py-2">
        <div class="d-flex justify-content-between">
          <strong>${escapeHtml(message.From.Username)}</strong>
          <small class="text-muted">${formatDate(message.Timestamp)}</small>
        </div>
        <p class="mb-1">${escapeHtml(message.Content.Message || 'Archivo adjunto')}</p>
        <div class="d-flex align-items-center">
          <small class="text-muted me-3">
            <i class="fas fa-file me-1"></i>Archivo adjunto
          </small>
          <button class="btn btn-sm btn-outline-primary" onclick="downloadFile('${escapeHtml(message.FileName)}')">
            <i class="fas fa-download me-1"></i>Descargar
          </button>
        </div>
      </div>
    `;
  }
  
  return `
    <div class="border-bottom border-gray-200 py-2">
      <div class="d-flex justify-content-between">
        <strong>${escapeHtml(message.From.Username)}</strong>
        <small class="text-muted">${formatDate(message.Timestamp)}</small>
      </div>
      <p class="mb-1">${escapeHtml(message.Content.Message)}</p>
      <div class="d-flex align-items-center">
        <small class="text-muted me-3">
          <i class="fas fa-heart me-1"></i>${message.Content.Likes || 0}
        </small>
        ${message.FileName ? `<small class="text-muted"><i class="fas fa-file me-1"></i>${escapeHtml(message.FileName)}</small>` : ''}
      </div>
    </div>
  `;
}

// Handle message submission
async function handleMessageSubmit(e, tablonId) {
  e.preventDefault();
  
  const form = e.target;
  const input = form.querySelector('input');
  const message = input.value.trim();
  
  if (!message) return;
  
  try {
    const response = await fetch(`/api/addMessage?tablon_id=${tablonId}&message=${encodeURIComponent(message)}`, {
      method: "POST",
    });
    
    if (response.ok) {
      input.value = '';
      refreshTablones();
    } else {
      throw new Error(`Error ${response.status}: ${await response.text()}`);
    }
  } catch (error) {
    logError("Error sending message:", error);
    showErrorNotification(`Error al enviar mensaje: ${error.message}`);
  }
}

// Delete tablón
async function deleteTablon(tablonId) {
  if (!confirm('¿Estás seguro de que quieres eliminar este tablón?')) return;
  
  try {
    const response = await fetch(`/api/deleteTablon?id=${tablonId}`, {
      method: "DELETE",
      headers: {
        "Authorization": token,
      },
    });
    
    if (response.ok) {
      showSuccessNotification("Tablón eliminado correctamente");
      refreshTablones();
    } else {
      throw new Error(`Error ${response.status}: ${await response.text()}`);
    }
  } catch (error) {
    logError("Error deleting tablón:", error);
    showErrorNotification(`Error al eliminar tablón: ${error.message}`);
  }
}

// Update security settings
function updateSecuritySettings() {
  const anonymousMode = document.getElementById('anonymousMode').checked;
  const encryptMessages = document.getElementById('encryptMessages').checked;
  const onionRouting = document.getElementById('onionRouting').checked;
  
  // In a real implementation, this would send the settings to the server
  logInfo(`Security settings updated - Anonymous: ${anonymousMode}, Encrypt: ${encryptMessages}, Onion: ${onionRouting}`);
  
  // Update UI indicators
  updateSecurityIndicators(anonymousMode, encryptMessages, onionRouting);
}

// Update security indicators in UI
function updateSecurityIndicators(anonymousMode, encryptMessages, onionRouting) {
  // This would update visual indicators in the UI
  logDebug(`Security indicators updated - Anonymous: ${anonymousMode}, Encrypt: ${encryptMessages}, Onion: ${onionRouting}`);
}

// Render pagination
function renderPagination(totalPages) {
  const pagination = document.getElementById('pagination');
  
  if (totalPages <= 1) {
    pagination.innerHTML = '';
    return;
  }
  
  let html = '';
  
  // Previous button
  html += `
    <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
      <a class="page-link" href="#" data-page="${currentPage - 1}">
        <i class="fas fa-chevron-left"></i>
      </a>
    </li>
  `;
  
  // Page numbers
  for (let i = 1; i <= totalPages; i++) {
    html += `
      <li class="page-item ${i === currentPage ? 'active' : ''}">
        <a class="page-link" href="#" data-page="${i}">${i}</a>
      </li>
    `;
  }
  
  // Next button
  html += `
    <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
      <a class="page-link" href="#" data-page="${currentPage + 1}">
        <i class="fas fa-chevron-right"></i>
      </a>
    </li>
  `;
  
  pagination.innerHTML = html;
  
  // Add event listeners to pagination links
  pagination.querySelectorAll('.page-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const page = parseInt(link.getAttribute('data-page'));
      if (page && page !== currentPage) {
        currentPage = page;
        displayTablones(filteredTablones);
      }
    });
  });
}

// Start auto-refresh
function startAutoRefresh() {
  if (refreshStatus.refreshIntervalId) {
    clearInterval(refreshStatus.refreshIntervalId);
  }
  
  refreshStatus.refreshIntervalId = setInterval(() => {
    if (token && document.getElementById('appSection').classList.contains('d-none') === false) {
      refreshTablones();
    }
  }, refreshStatus.currentRefreshInterval);
}

// File transfer functions
function handleFileSelection(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  selectedFile = file;
  document.getElementById('selectedFile').value = file.name;
  
  // Show send file modal
  new bootstrap.Modal(document.getElementById('sendFileModal')).show();
}

function updateFileTablonSelector(tablones) {
  const selector = document.getElementById('fileTablon');
  selector.innerHTML = '<option value="">Selecciona un tablón</option>';
  
  tablones.forEach(tablon => {
    const option = document.createElement('option');
    option.value = tablon.ID;
    option.textContent = tablon.Name;
    selector.appendChild(option);
  });
}

async function handleSendFile(e) {
  e.preventDefault();
  
  if (!selectedFile) {
    showErrorNotification('No se ha seleccionado ningún archivo');
    return;
  }
  
  const message = document.getElementById('fileMessage').value;
  const tablonId = document.getElementById('fileTablon').value;
  
  if (!tablonId) {
    showErrorNotification('Por favor selecciona un tablón de destino');
    return;
  }
  
  try {
    // Create FormData for file upload
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    // Send file to server
    const response = await fetch('/api/sendBinary', {
      method: 'POST',
      body: formData
    });
    
    if (response.ok) {
      showSuccessNotification('Archivo enviado correctamente');
      
      // Close modal and reset form
      bootstrap.Modal.getInstance(document.getElementById('sendFileModal')).hide();
      document.getElementById('sendFileForm').reset();
      selectedFile = null;
      document.getElementById('fileInput').value = '';
      
      // Refresh tablones to show the new file message
      refreshTablones();
    } else {
      throw new Error(`Error ${response.status}: ${await response.text()}`);
    }
  } catch (error) {
    logError("Error sending file:", error);
    showErrorNotification(`Error al enviar archivo: ${error.message}`);
  }
}

// Utility functions
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  
  return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleString('es-ES', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Client-side encryption
function generateEncryptionKey() {
  // Generate a random 32-byte key for AES-256
  const keyArray = new Uint8Array(32);
  crypto.getRandomValues(keyArray);
  const key = Array.from(keyArray).map(b => b.toString(16).padStart(2, '0')).join('');
  
  document.getElementById('encryptionKey').value = key;
  showSuccessNotification('Nueva clave generada. Recuerda guardarla en un lugar seguro.');
  logInfo('New encryption key generated');
}

function exportEncryptionKey() {
  const key = document.getElementById('encryptionKey').value;
  if (!key) {
    showErrorNotification('No hay clave para exportar');
    return;
  }
  
  // Create a Blob with the key
  const blob = new Blob([key], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  
  // Create a temporary link to trigger download
  const a = document.createElement('a');
  a.href = url;
  a.download = 'p2p-encryption-key.key';
  document.body.appendChild(a);
  a.click();
  
  // Clean up
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
  
  showSuccessNotification('Clave exportada correctamente');
  logInfo('Encryption key exported');
}

function importEncryptionKey(event) {
  const file = event.target.files[0];
  if (!file) return;
  
  const reader = new FileReader();
  reader.onload = function(e) {
    const key = e.target.result.trim();
    
    // Basic validation: check if it's a hex string of appropriate length
    if (/^[0-9a-fA-F]{64}$/.test(key)) {
      document.getElementById('encryptionKey').value = key;
      showSuccessNotification('Clave importada correctamente');
      logInfo('Encryption key imported');
    } else {
      showErrorNotification('Formato de clave inválido. Debe ser una cadena hexadecimal de 64 caracteres.');
      logError('Invalid key format during import');
    }
  };
  
  reader.readAsText(file);
}

// Export functions for testing
export {
  handleLogin,
  handleLogout,
  handleCreateTablon,
  refreshTablones,
  deleteTablon,
  updateSecuritySettings
};