// Importar utilidades
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

// Variables globales
let token = localStorage.getItem("token");
let filteredTablones = [];
let currentPage = 1;
const itemsPerPage = 5;
let lastFetchedData = null; // Para comparar y solo actualizar cuando hay cambios
let refreshStatus = {
  isRefreshing: false,
  autoRefreshEnabled: true,
  refreshIntervalId: null,
  currentRefreshInterval: 30000, // 30 segundos por defecto
  lastRefreshTime: null,
};

// Función para iniciar sesión
async function login(username, password, peerId, photo) {
  try {
    logInfo(`Intentando iniciar sesión con usuario: ${username}`);

    // Mostrar indicador de carga
    const loginButton = document.querySelector(
      '#loginFormElement button[type="submit"]'
    );
    if (loginButton) {
      const originalText = loginButton.innerHTML;
      loginButton.innerHTML =
        '<i class="fas fa-spinner fa-spin"></i> Iniciando sesión...';
      loginButton.disabled = true;
    }

    const response = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password, peerId, photo }),
    });

    if (response.ok) {
      const data = await response.json();
      token = data.token;
      localStorage.setItem("token", token);
      document.getElementById("loginForm").style.display = "none";
      showSuccessNotification("Sesión iniciada correctamente");
      logInfo("Inicio de sesión exitoso");
      refreshTablones();
    } else {
      const errorText = await response.text();
      logError(`Error de inicio de sesión: ${response.status} - ${errorText}`);
      showErrorNotification("Credenciales inválidas");
    }
  } catch (error) {
    logError("Error durante el inicio de sesión:", error);
    showErrorNotification(`Error de conexión: ${error.message}`);
  } finally {
    // Restaurar botón
    const loginButton = document.querySelector(
      '#loginFormElement button[type="submit"]'
    );
    if (loginButton) {
      loginButton.innerHTML = "Iniciar Sesión";
      loginButton.disabled = false;
    }
  }
}

// Función para crear un tablón
async function createTablon(name, message, geo) {
  try {
    if (!token) {
      const errorMsg = "No hay token disponible. Inicia sesión primero.";
      logError(errorMsg);
      showErrorNotification(errorMsg);
      throw new Error(errorMsg);
    }

    logInfo(`Creando tablón: ${name}`);
    const url = `/api/createTablon?name=${encodeURIComponent(
      name
    )}&mensaje=${encodeURIComponent(message)}&geo=${encodeURIComponent(geo)}`;

    const data = await safeFetch(url, {
      method: "POST",
      headers: {
        Authorization: token,
      },
    });

    logInfo("Tablón creado correctamente");
    return data || { success: true, messageId: "unknown" };
  } catch (error) {
    logError("Error al crear el tablón:", error);
    showErrorNotification(`Error al crear el tablón: ${error.message}`);
    throw error;
  }
}

// Función para obtener todos los tablones
async function getTablones() {
  try {
    logDebug("Obteniendo lista de tablones");
    const data = await safeFetch("/api/readTablon");
    return Array.isArray(data) ? data : [];
  } catch (error) {
    logError("Error al obtener tablones:", error);
    showErrorNotification(`Error al cargar tablones: ${error.message}`);
    return [];
  }
}

// Función para eliminar un tablón
async function deleteTablon(id) {
  try {
    if (!token) {
      const errorMsg = "No hay token disponible. Inicia sesión primero.";
      logError(errorMsg);
      showErrorNotification(errorMsg);
      throw new Error(errorMsg);
    }

    logInfo(`Eliminando tablón: ${id}`);
    const data = await safeFetch(`/api/deleteTablon?id=${id}`, {
      method: "DELETE",
      headers: {
        Authorization: token,
      },
    });

    showSuccessNotification("Tablón eliminado correctamente");
    return data;
  } catch (error) {
    logError("Error al eliminar tablón:", error);
    showErrorNotification(`Error al eliminar tablón: ${error.message}`);
    throw error;
  }
}

// Función para añadir un mensaje a un tablón
async function addMessage(tablonId, message) {
  try {
    logInfo(`Añadiendo mensaje al tablón: ${tablonId}`);
    const data = await safeFetch(
      `/api/addMessage?tablon_id=${tablonId}&message=${encodeURIComponent(
        message
      )}`,
      {
        method: "POST",
      }
    );

    showSuccessNotification("Mensaje añadido correctamente");
    return data;
  } catch (error) {
    logError("Error al añadir mensaje:", error);
    showErrorNotification(`Error al añadir mensaje: ${error.message}`);
    throw error;
  }
}

// Función para eliminar un mensaje
async function deleteMessage(tablonId, messageId) {
  try {
    if (!token) {
      const errorMsg = "No hay token disponible. Inicia sesión primero.";
      logError(errorMsg);
      showErrorNotification(errorMsg);
      throw new Error(errorMsg);
    }

    logInfo(`Eliminando mensaje: ${messageId} del tablón: ${tablonId}`);
    const data = await safeFetch(
      `/api/deleteMessage?tablonId=${tablonId}&messageId=${messageId}`,
      {
        method: "DELETE",
        headers: {
          Authorization: token,
        },
      }
    );

    showSuccessNotification("Mensaje eliminado correctamente");
    return data;
  } catch (error) {
    logError("Error al eliminar mensaje:", error);
    showErrorNotification(`Error al eliminar mensaje: ${error.message}`);
    throw error;
  }
}

// Función para dar like a un mensaje
async function likeMessage(tablonId, messageId) {
  try {
    logInfo(`Dando like al mensaje: ${messageId} del tablón: ${tablonId}`);
    const data = await safeFetch(
      `/api/likeMessage?tablonId=${tablonId}&messageId=${messageId}`,
      {
        method: "POST",
      }
    );

    return data;
  } catch (error) {
    logError("Error al dar like al mensaje:", error);
    showErrorNotification(`Error al dar like: ${error.message}`);
    throw error;
  }
}

// Función para filtrar tablones por nombre
function filterTablonesByName(query) {
  return filteredTablones.filter(
    (tablon) =>
      tablon.name && tablon.name.toLowerCase().includes(query.toLowerCase())
  );
}

// Función para renderizar los tablones con mejor visualización
function renderTablones(tablones) {
  const tablonesListElement = document.getElementById("tablonesList");

  // Guardar el scroll actual para restaurarlo después
  const scrollPosition = tablonesListElement.scrollTop;

  // Mostrar indicador de carga
  tablonesListElement.innerHTML =
    "<div class='loading-indicator'><i class='fas fa-spinner fa-spin'></i> Cargando tablones...</div>";

  // Verificar si hay tablones para mostrar
  if (!Array.isArray(tablones) || tablones.length === 0) {
    tablonesListElement.innerHTML = `
      <div class="alert alert-info">
        <i class="fas fa-info-circle me-2"></i>
        <span>Buscando nodos y tablones disponibles. Si no aparece ninguno, puedes crear uno nuevo.</span>
      </div>
    `;
    return;
  }

  // Crear un fragmento para mejorar el rendimiento
  const fragment = document.createDocumentFragment();

  // Renderizar cada tablón
  tablones.forEach((tablon) => {
    const tablonElement = document.createElement("div");
    tablonElement.className = "card tablon mb-4 shadow-sm";
    tablonElement.dataset.tablonId = tablon.id; // Para facilitar la actualización parcial

    // Crear el encabezado del tablón
    const tablonHeader = document.createElement("div");
    tablonHeader.className =
      "card-header d-flex justify-content-between align-items-center";
    tablonHeader.innerHTML = `
      <h3 class="mb-0">
        <i class="fas fa-clipboard-list me-2"></i>
        ${tablon.name}
        ${
          tablon.geo
            ? `<small class="text-muted"><i class="fas fa-map-marker-alt me-1"></i>${tablon.geo}</small>`
            : ""
        }
      </h3>
      <div>
        <button class="btn btn-sm btn-danger" onclick="handleDeleteTablon('${
          tablon.id
        }')">
          <i class="fas fa-trash me-1"></i> Eliminar
        </button>
      </div>
    `;

    // Crear el cuerpo del tablón
    const tablonBody = document.createElement("div");
    tablonBody.className = "card-body";

    // Sección de mensajes
    const messagesSection = document.createElement("div");
    messagesSection.className = "messages mb-3";

    // Verificar si hay mensajes
    if (tablon.messages && tablon.messages.length > 0) {
      // Ordenar mensajes por fecha (más recientes primero)
      const sortedMessages = [...tablon.messages].sort(
        (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
      );

      // Crear cada mensaje
      sortedMessages.forEach((message) => {
        const messageElement = document.createElement("div");
        messageElement.className = "message card mb-2";
        messageElement.dataset.messageId = message.id; // Para facilitar la actualización parcial

        messageElement.innerHTML = `
          <div class="card-body">
            <p class="message-content mb-2">${message.content.message}</p>
            <div class="d-flex justify-content-between align-items-center">
              <small class="text-muted">
                <i class="far fa-clock me-1"></i>
                ${new Date(message.timestamp).toLocaleString()}
              </small>
              <div class="btn-group">
                <button class="btn btn-sm btn-outline-primary" onclick="handleLikeMessage('${
                  tablon.id
                }', '${message.id}')">
                  <i class="fas fa-eye me-1"></i> ${message.content.likes || 0}
                </button>
                <button class="btn btn-sm btn-outline-danger" onclick="handleDeleteMessage('${
                  tablon.id
                }', '${message.id}')">
                  <i class="fas fa-trash"></i>
                </button>
              </div>
            </div>
          </div>
        `;

        messagesSection.appendChild(messageElement);
      });
    } else {
      // Mostrar mensaje cuando no hay mensajes
      messagesSection.innerHTML = `
        <div class="alert alert-light text-center">
          <i class="far fa-comment-dots me-2"></i>
          No hay mensajes en este tablón. ¡Sé el primero en escribir!
        </div>
      `;
    }

    // Formulario para añadir mensajes
    const messageForm = document.createElement("form");
    messageForm.className = "mt-3";
    messageForm.innerHTML = `
      <div class="input-group">
        <input type="text" class="form-control" placeholder="Escribe un nuevo mensaje..." required>
        <button class="btn btn-primary" type="submit">
          <i class="fas fa-paper-plane me-1"></i> Enviar
        </button>
      </div>
    `;

    // Añadir event listener al formulario
    messageForm.addEventListener("submit", (event) =>
      handleAddMessage(event, tablon.id)
    );

    // Ensamblar el tablón
    tablonBody.appendChild(messagesSection);
    tablonBody.appendChild(messageForm);
    tablonElement.appendChild(tablonHeader);
    tablonElement.appendChild(tablonBody);

    // Añadir al fragmento
    fragment.appendChild(tablonElement);
  });

  // Limpiar y añadir todos los tablones de una vez
  tablonesListElement.innerHTML = "";
  tablonesListElement.appendChild(fragment);

  // Restaurar la posición de scroll
  tablonesListElement.scrollTop = scrollPosition;

  // Mostrar indicador de última actualización
  const lastUpdateIndicator = document.getElementById("lastUpdateIndicator");
  if (lastUpdateIndicator) {
    const now = new Date();
    lastUpdateIndicator.textContent = `Última actualización: ${now.toLocaleTimeString()}`;
    refreshStatus.lastRefreshTime = now;
  }
}

// Manejadores de eventos mejorados
async function handleCreateTablon(event) {
  event.preventDefault();

  try {
    const name = document.getElementById("tablonName").value;
    const message = document.getElementById("tablonMessage").value;
    const geo = document.getElementById("tablonGeo").value || "";

    // Validar campos
    if (!name || !message) {
      showErrorNotification("Por favor, completa los campos obligatorios");
      return;
    }

    // Mostrar indicador de carga
    const submitButton = event.target.querySelector('button[type="submit"]');
    if (submitButton) {
      const originalText = submitButton.innerHTML;
      submitButton.innerHTML =
        '<i class="fas fa-spinner fa-spin"></i> Creando...';
      submitButton.disabled = true;

      try {
        await createTablon(name, message, geo);

        // Limpiar formulario
        document.getElementById("tablonName").value = "";
        document.getElementById("tablonMessage").value = "";
        document.getElementById("tablonGeo").value = "";

        // Mostrar mensaje de éxito
        showSuccessNotification("Tablón creado correctamente");

        // Actualizar lista de tablones
        refreshTablones();
      } finally {
        // Restaurar botón
        submitButton.innerHTML = originalText;
        submitButton.disabled = false;
      }
    } else {
      await createTablon(name, message, geo);
      refreshTablones();
    }
  } catch (error) {
    logError("Error al crear el tablón:", error);
    showErrorNotification(`Error al crear el tablón: ${error.message}`);
  }
}

async function handleDeleteTablon(id) {
  try {
    // Pedir confirmación
    if (
      !confirm(
        "\u00bfEstás seguro de que deseas eliminar este tablón? Esta acción no se puede deshacer."
      )
    ) {
      return;
    }

    // Mostrar indicador de carga en el tablón
    const tablonElement = document.querySelector(`[data-tablon-id="${id}"]`);
    if (tablonElement) {
      tablonElement.classList.add("opacity-50");
      const deleteButton = tablonElement.querySelector(
        `button[onclick="handleDeleteTablon('${id}')"]`
      );
      if (deleteButton) {
        const originalText = deleteButton.innerHTML;
        deleteButton.innerHTML =
          '<i class="fas fa-spinner fa-spin"></i> Eliminando...';
        deleteButton.disabled = true;
      }
    }

    await deleteTablon(id);
    refreshTablones();
  } catch (error) {
    logError("Error al eliminar el tablón:", error);
    showErrorNotification(`Error al eliminar el tablón: ${error.message}`);

    // Restaurar el estado del tablón si hubo error
    const tablonElement = document.querySelector(`[data-tablon-id="${id}"]`);
    if (tablonElement) {
      tablonElement.classList.remove("opacity-50");
      const deleteButton = tablonElement.querySelector(
        `button[onclick="handleDeleteTablon('${id}')"]`
      );
      if (deleteButton) {
        deleteButton.innerHTML = '<i class="fas fa-trash me-1"></i> Eliminar';
        deleteButton.disabled = false;
      }
    }
  }
}

async function handleAddMessage(event, tablonId) {
  event.preventDefault();

  try {
    const inputElement = event.target.querySelector("input");
    const message = inputElement.value.trim();

    if (!message) {
      showErrorNotification("El mensaje no puede estar vacío");
      return;
    }

    // Mostrar indicador de carga
    const submitButton = event.target.querySelector('button[type="submit"]');
    if (submitButton) {
      const originalText = submitButton.innerHTML;
      submitButton.innerHTML =
        '<i class="fas fa-spinner fa-spin"></i> Enviando...';
      submitButton.disabled = true;

      try {
        await addMessage(tablonId, message);

        // Limpiar el campo de entrada
        inputElement.value = "";

        // Actualizar solo este tablón
        const tablonElement = document.querySelector(
          `[data-tablon-id="${tablonId}"]`
        );
        if (tablonElement) {
          // Actualizar solo los mensajes de este tablón
          const updatedTablones = await getTablones();
          const updatedTablon = updatedTablones.find((t) => t.id === tablonId);

          if (updatedTablon) {
            // Actualizar la sección de mensajes
            const messagesSection = tablonElement.querySelector(".messages");
            if (messagesSection) {
              // Ordenar mensajes por fecha (más recientes primero)
              const sortedMessages = [...updatedTablon.messages].sort(
                (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
              );

              // Limpiar y recrear los mensajes
              messagesSection.innerHTML = "";

              if (sortedMessages.length > 0) {
                sortedMessages.forEach((message) => {
                  const messageElement = document.createElement("div");
                  messageElement.className = "message card mb-2";
                  messageElement.dataset.messageId = message.id;

                  messageElement.innerHTML = `
                    <div class="card-body">
                      <p class="message-content mb-2">${
                        message.content.message
                      }</p>
                      <div class="d-flex justify-content-between align-items-center">
                        <small class="text-muted">
                          <i class="far fa-clock me-1"></i>
                          ${new Date(message.timestamp).toLocaleString()}
                        </small>
                        <div class="btn-group">
                          <button class="btn btn-sm btn-outline-primary" onclick="handleLikeMessage('${tablonId}', '${
                    message.id
                  }')">
                            <i class="fas fa-eye me-1"></i> ${
                              message.content.likes || 0
                            }
                          </button>
                          <button class="btn btn-sm btn-outline-danger" onclick="handleDeleteMessage('${tablonId}', '${
                    message.id
                  }')">
                            <i class="fas fa-trash"></i>
                          </button>
                        </div>
                      </div>
                    </div>
                  `;

                  messagesSection.appendChild(messageElement);
                });
              } else {
                messagesSection.innerHTML = `
                  <div class="alert alert-light text-center">
                    <i class="far fa-comment-dots me-2"></i>
                    No hay mensajes en este tablón. ¡Sé el primero en escribir!
                  </div>
                `;
              }
            }
          }
        } else {
          // Si no se puede encontrar el tablón, actualizar todos
          refreshTablones();
        }
      } finally {
        // Restaurar botón
        submitButton.innerHTML = originalText;
        submitButton.disabled = false;
      }
    } else {
      await addMessage(tablonId, message);
      refreshTablones();
    }
  } catch (error) {
    logError("Error al añadir mensaje:", error);
    showErrorNotification(`Error al añadir mensaje: ${error.message}`);
  }
}

async function handleDeleteMessage(tablonId, messageId) {
  try {
    // Pedir confirmación
    if (!confirm("\u00bfEstás seguro de que deseas eliminar este mensaje?")) {
      return;
    }

    // Mostrar indicador de carga en el mensaje
    const messageElement = document.querySelector(
      `[data-message-id="${messageId}"]`
    );
    if (messageElement) {
      messageElement.classList.add("opacity-50");
      const deleteButton = messageElement.querySelector(
        `button[onclick="handleDeleteMessage('${tablonId}', '${messageId}')"]`
      );
      if (deleteButton) {
        deleteButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        deleteButton.disabled = true;
      }
    }

    await deleteMessage(tablonId, messageId);

    // Eliminar el mensaje del DOM con animación
    if (messageElement) {
      messageElement.style.transition = "all 0.3s ease";
      messageElement.style.maxHeight = "0";
      messageElement.style.opacity = "0";
      messageElement.style.overflow = "hidden";

      setTimeout(() => {
        if (messageElement.parentNode) {
          messageElement.parentNode.removeChild(messageElement);
        }
      }, 300);
    } else {
      refreshTablones();
    }
  } catch (error) {
    logError("Error al eliminar mensaje:", error);
    showErrorNotification(`Error al eliminar mensaje: ${error.message}`);

    // Restaurar el estado del mensaje si hubo error
    const messageElement = document.querySelector(
      `[data-message-id="${messageId}"]`
    );
    if (messageElement) {
      messageElement.classList.remove("opacity-50");
      const deleteButton = messageElement.querySelector(
        `button[onclick="handleDeleteMessage('${tablonId}', '${messageId}')"]`
      );
      if (deleteButton) {
        deleteButton.innerHTML = '<i class="fas fa-trash"></i>';
        deleteButton.disabled = false;
      }
    }
  }
}

async function handleLikeMessage(tablonId, messageId) {
  try {
    // Mostrar indicador de carga en el botón de like
    const likeButton = document.querySelector(
      `button[onclick="handleLikeMessage('${tablonId}', '${messageId}')"]`
    );
    if (likeButton) {
      const originalText = likeButton.innerHTML;
      likeButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
      likeButton.disabled = true;

      const result = await likeMessage(tablonId, messageId);

      // Actualizar solo el contador de likes
      if (result && typeof result.likes !== "undefined") {
        likeButton.innerHTML = `<i class="fas fa-eye me-1"></i> ${result.likes}`;
      } else {
        // Si no podemos obtener el número actualizado, refrescar el tablón
        refreshTablones();
      }

      likeButton.disabled = false;
    } else {
      await likeMessage(tablonId, messageId);
      refreshTablones();
    }
  } catch (error) {
    logError("Error al dar like al mensaje:", error);
    showErrorNotification(`Error al dar like: ${error.message}`);

    // Restaurar el botón si hubo error
    const likeButton = document.querySelector(
      `button[onclick="handleLikeMessage('${tablonId}', '${messageId}')"]`
    );
    if (likeButton) {
      likeButton.innerHTML = '<i class="fas fa-eye me-1"></i> ?';
      likeButton.disabled = false;
    }
  }
}

// Sistema mejorado de actualización automática

/**
 * Función para refrescar la lista de tablones con paginación y actualización inteligente
 * Solo actualiza el contenido cuando hay cambios reales
 */
async function refreshTablones(forceRefresh = false) {
  // Evitar actualizaciones simultáneas o cuando está desactivado
  if (
    (refreshStatus.isRefreshing || !refreshStatus.autoRefreshEnabled) &&
    !forceRefresh
  ) {
    return;
  }

  try {
    refreshStatus.isRefreshing = true;

    // Actualizar indicador visual de estado
    const refreshIndicator = document.getElementById("refreshIndicator");
    if (refreshIndicator) {
      refreshIndicator.classList.add("refreshing");
      refreshIndicator.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i>';
    }

    // Obtener datos actualizados
    logDebug("Obteniendo tablones actualizados");
    const searchQuery = document.getElementById("searchInput").value;
    const allTablones = await getTablones();

    // Verificar si hay cambios reales comparando con los datos anteriores
    const hasChanges =
      forceRefresh ||
      !lastFetchedData ||
      JSON.stringify(allTablones) !== JSON.stringify(lastFetchedData);

    if (hasChanges) {
      logInfo("Cambios detectados, actualizando la interfaz");
      lastFetchedData = allTablones;

      // Filtrar y paginar
      filteredTablones = searchQuery
        ? filterTablonesByName(searchQuery)
        : allTablones;
      const paginatedTablones = paginate(
        filteredTablones,
        currentPage,
        itemsPerPage
      );

      // Renderizar
      renderTablones(paginatedTablones);
      renderPagination(filteredTablones.length);

      // Mostrar notificación de actualización si no es la primera carga
      if (!forceRefresh && refreshStatus.lastRefreshTime) {
        showInfoNotification("Contenido actualizado", 2000);
      }
    } else {
      logDebug("No hay cambios desde la última actualización");

      // Actualizar solo el indicador de última actualización
      const lastUpdateIndicator = document.getElementById(
        "lastUpdateIndicator"
      );
      if (lastUpdateIndicator) {
        const now = new Date();
        lastUpdateIndicator.textContent = `Última actualización: ${now.toLocaleTimeString()}`;
        refreshStatus.lastRefreshTime = now;
      }
    }
  } catch (error) {
    logError("Error al actualizar tablones:", error);
    showErrorNotification(`Error al actualizar: ${error.message}`);
  } finally {
    refreshStatus.isRefreshing = false;

    // Actualizar indicador visual de estado
    const refreshIndicator = document.getElementById("refreshIndicator");
    if (refreshIndicator) {
      refreshIndicator.classList.remove("refreshing");
      refreshIndicator.innerHTML = '<i class="fas fa-sync-alt"></i>';
    }
  }
}

/**
 * Función para iniciar la actualización automática
 */
function startAutoRefresh() {
  if (refreshStatus.refreshIntervalId) {
    stopAutoRefresh(); // Detener el intervalo anterior si existe
  }

  logInfo(
    `Iniciando actualización automática cada ${
      refreshStatus.currentRefreshInterval / 1000
    } segundos`
  );
  refreshStatus.refreshIntervalId = setInterval(() => {
    refreshTablones();
  }, refreshStatus.currentRefreshInterval);

  refreshStatus.autoRefreshEnabled = true;

  // Actualizar el estado del toggle en la interfaz
  const autoRefreshToggle = document.getElementById("autoRefreshToggle");
  if (autoRefreshToggle) {
    autoRefreshToggle.checked = true;
  }
}

/**
 * Función para detener la actualización automática
 */
function stopAutoRefresh() {
  if (refreshStatus.refreshIntervalId) {
    logInfo("Deteniendo actualización automática");
    clearInterval(refreshStatus.refreshIntervalId);
    refreshStatus.refreshIntervalId = null;
    refreshStatus.autoRefreshEnabled = false;

    // Actualizar el estado del toggle en la interfaz
    const autoRefreshToggle = document.getElementById("autoRefreshToggle");
    if (autoRefreshToggle) {
      autoRefreshToggle.checked = false;
    }
  }
}

// Configurar event listeners para controles de actualización
document.addEventListener("DOMContentLoaded", function () {
  // Manejador para el toggle de auto actualización
  const autoRefreshToggle = document.getElementById("autoRefreshToggle");
  if (autoRefreshToggle) {
    autoRefreshToggle.addEventListener("change", function (event) {
      if (event.target.checked) {
        startAutoRefresh();
        showInfoNotification("Actualización automática activada");
      } else {
        stopAutoRefresh();
        showInfoNotification("Actualización automática desactivada");
      }
    });
  }

  // Manejador para el cambio de intervalo
  const refreshIntervalSelect = document.getElementById("refreshInterval");
  if (refreshIntervalSelect) {
    refreshIntervalSelect.addEventListener("change", function (event) {
      const newInterval = parseInt(event.target.value) * 1000; // Convertir a milisegundos
      refreshStatus.currentRefreshInterval = newInterval;

      if (refreshStatus.autoRefreshEnabled) {
        stopAutoRefresh(); // Detener la anterior
        startAutoRefresh(); // Iniciar con el nuevo intervalo
        showInfoNotification(
          `Intervalo cambiado a ${newInterval / 1000} segundos`
        );
      }
    });
  }

  // Botón de actualización manual
  const refreshButton = document.getElementById("refreshButton");
  if (refreshButton) {
    refreshButton.addEventListener("click", function () {
      refreshTablones(true); // Forzar actualización
    });
  }
});

// Inicialización cuando hay token
if (token) {
  document.getElementById("loginForm").style.display = "none";
  refreshTablones(true); // Forzar primera carga
}

// Iniciar actualización automática por defecto
startAutoRefresh();

// Función para paginar los tablones
function paginate(array, page, pageSize) {
  return array.slice((page - 1) * pageSize, page * pageSize);
}

// Función para renderizar la paginación
function renderPagination(totalItems) {
  const paginationElement = document.getElementById("pagination");
  paginationElement.innerHTML = "";

  const totalPages = Math.ceil(totalItems / itemsPerPage);

  for (let i = 1; i <= totalPages; i++) {
    const li = document.createElement("li");
    li.className = `page-item ${i === currentPage ? "active" : ""}`;
    li.innerHTML = `<a class="page-link" href="#">${i}</a>`;
    li.addEventListener("click", function (event) {
      event.preventDefault();
      currentPage = i;
      refreshTablones();
    });
    paginationElement.appendChild(li);
  }
}

// Inicialización
// Manejador de evento para el formulario de inicio de sesión
document
  .getElementById("loginFormElement")
  .addEventListener("submit", async function (event) {
    event.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const peerId = document.getElementById("peerId").value;
    const photo = document.getElementById("photo").value;
    await login(username, password, peerId, photo);
  });

// Verificar si hay un token almacenado al cargar la página
if (token) {
  document.getElementById("loginForm").style.display = "none";
  refreshTablones();
}
//wpa - Deshabilitado temporalmente para evitar errores
/*
if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/service-worker.js")
    .then(function (registration) {
      console.log("Service Worker registrado con éxito:", registration);
    })
    .catch(function (error) {
      console.log("Error al registrar el Service Worker:", error);
    });
}
*/

/**
 * Función mejorada para obtener y mostrar datos de la API
 */
async function fetchRecibe() {
  try {
    // Verificar si hay token
    if (!token) {
      logWarning("No hay token disponible. Inicia sesión primero.");
      showErrorNotification("Debes iniciar sesión para ver los datos");
      return;
    }

    // Seleccionar el contenedor
    const slidingTextContainer = document.getElementById(
      "slidingTextContainer"
    );
    if (!slidingTextContainer) {
      logError("No se encontró el contenedor slidingTextContainer");
      return;
    }

    // Mostrar indicador de carga con animación
    slidingTextContainer.innerHTML = `
      <div class="text-center p-4 fade-in">
        <div class="spinner-border text-primary mb-3" role="status">
          <span class="visually-hidden">Cargando...</span>
        </div>
        <p class="text-muted">Cargando datos...</p>
      </div>
    `;

    try {
      // Usar nuestra función safeFetch para manejar errores de forma consistente
      logInfo("Obteniendo datos de la API");
      const data = await safeFetch("/api/recibe", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: token,
        },
      });

      // Verificar que data es un array
      if (!data || !Array.isArray(data) || data.length === 0) {
        slidingTextContainer.innerHTML = `
          <div class="alert alert-info fade-in">
            <i class="fas fa-info-circle me-2"></i>
            No hay datos disponibles en este momento.
          </div>
        `;
        return;
      }

      logInfo(`Datos recibidos: ${data.length} elementos`);

      // Limpiar el contenedor
      slidingTextContainer.innerHTML = "";

      // Crear un fragmento para mejorar el rendimiento
      const fragment = document.createDocumentFragment();

      // Generar dinámicamente los items con mejor visualización
      data.forEach((item, index) => {
        try {
          // Verificar que item y sus propiedades existen
          if (!item) {
            logWarning("Item inválido:", item);
            return;
          }

          // Verificar la estructura del item
          const content = item.Content || item.content || {};
          const title = content.Title || content.title || "Sin título";
          const message = content.Message || content.message || "Sin mensaje";
          const timestamp =
            item.Timestamp || item.timestamp || new Date().toISOString();

          // Crear el elemento de tarjeta
          const cardElement = document.createElement("div");
          cardElement.className = `card mb-3 fade-in`;
          cardElement.style.animationDelay = `${index * 0.1}s`;

          cardElement.innerHTML = `
            <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
              <h5 class="card-title mb-0">${title}</h5>
              <small><i class="far fa-clock me-1"></i>${new Date(
                timestamp
              ).toLocaleString()}</small>
            </div>
            <div class="card-body">
              <p class="card-text">${message}</p>
            </div>
          `;

          fragment.appendChild(cardElement);
        } catch (itemError) {
          logError("Error al procesar item:", itemError);
        }
      });

      // Añadir todos los elementos de una vez
      slidingTextContainer.appendChild(fragment);

      // Mostrar notificación de éxito
      showSuccessNotification(`${data.length} mensajes cargados correctamente`);
    } catch (fetchError) {
      logError("Error al obtener datos:", fetchError);
      slidingTextContainer.innerHTML = `
        <div class="alert alert-danger fade-in">
          <i class="fas fa-exclamation-triangle me-2"></i>
          Error al obtener datos: ${fetchError.message}
          <button class="btn btn-sm btn-outline-danger mt-2" onclick="fetchRecibe()">
            <i class="fas fa-sync-alt me-1"></i> Reintentar
          </button>
        </div>
      `;
      showErrorNotification(`Error al cargar datos: ${fetchError.message}`);
    }
  } catch (error) {
    logError("Error general en fetchRecibe:", error);
    showErrorNotification(`Error inesperado: ${error.message}`);
  }
}

/**
 * Exponer funciones necesarias al ámbito global para los atributos onclick en HTML
 */
// Guardar una referencia al objeto window antes de que se aplique el modo estricto
const globalThis = window;

// Exponer las funciones necesarias al ámbito global
globalThis.handleDeleteTablon = handleDeleteTablon;
globalThis.handleDeleteMessage = handleDeleteMessage;
globalThis.handleLikeMessage = handleLikeMessage;
globalThis.handleAddMessage = handleAddMessage;
globalThis.fetchRecibe = fetchRecibe;
globalThis.refreshTablones = refreshTablones;

/**
 * Configuración de event listeners y inicialización
 */
document.addEventListener("DOMContentLoaded", () => {
  logInfo("Inicializando aplicación");

  // Configurar event listeners para elementos de la interfaz
  const createTablonForm = document.getElementById("createTablonForm");
  if (createTablonForm) {
    createTablonForm.addEventListener("submit", handleCreateTablon);
    logDebug(
      "Event listener configurado para el formulario de creación de tablones"
    );
  }

  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    // Usar debounce para evitar demasiadas actualizaciones durante la escritura
    searchInput.addEventListener(
      "input",
      debounce(() => {
        refreshTablones(true);
      }, 300)
    );
    logDebug("Event listener configurado para la búsqueda");
  }

  const fetchDataButton = document.getElementById("fetchDataButton");
  if (fetchDataButton) {
    fetchDataButton.addEventListener("click", (event) => {
      event.preventDefault();
      fetchRecibe();
    });
    logDebug("Event listener configurado para el botón de carga de datos");
  }

  // Inicializar componentes
  fetchRecibe(); // Cargar datos iniciales
  refreshTablones(true); // Forzar primera carga de tablones

  // Configurar temporizador para expirar el token (seguridad)
  const tokenExpirationTime = 3600000; // 1 hora
  logInfo(
    `Configurando expiración de token cada ${
      tokenExpirationTime / 1000 / 60
    } minutos`
  );

  setInterval(() => {
    localStorage.removeItem("token");
    token = null;
    logInfo("Token eliminado por seguridad");
    showInfoNotification(
      "Tu sesión ha expirado. Por favor, inicia sesión nuevamente."
    );

    // Mostrar formulario de login
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
      loginForm.style.display = "block";
    }
  }, tokenExpirationTime);

  logInfo("Aplicación inicializada correctamente");
});
