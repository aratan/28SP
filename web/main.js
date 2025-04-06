let token = localStorage.getItem("token");
let filteredTablones = [];
let currentPage = 1;
const itemsPerPage = 5;

// Función para iniciar sesión
async function login(username, password, peerId, photo) {
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
    refreshTablones();
  } else {
    alert("Credenciales inválidas");
  }
}

// Función para crear un tablón
// Modificar las funciones existentes para incluir el token en las peticiones
async function createTablon(name, message, geo) {
  try {
    if (!token) {
      throw new Error("No hay token disponible. Inicia sesión primero.");
    }

    const response = await fetch(
      `/api/createTablon?name=${encodeURIComponent(
        name
      )}&mensaje=${encodeURIComponent(message)}&geo=${encodeURIComponent(geo)}`,
      {
        method: "POST",
        headers: {
          Authorization: token,
        },
      }
    );

    if (!response.ok) {
      throw new Error(
        `Error al crear el grupo: ${response.status} ${response.statusText}`
      );
    }

    const text = await response.text();
    if (!text || text.trim() === "") {
      return { success: true, messageId: "unknown" };
    }

    try {
      return JSON.parse(text);
    } catch (parseError) {
      console.error(
        "Error al parsear la respuesta JSON:",
        parseError,
        "Texto recibido:",
        text
      );
      return { success: true, messageId: "unknown" };
    }
  } catch (error) {
    console.error("Error al crear el grupo:", error);
    throw error;
  }
}

// Función para obtener todos los tablones
async function getTablones() {
  const response = await fetch("/api/readTablon");
  const data = await response.json();
  return Array.isArray(data) ? data : [];
}

// Función para eliminar un tablón
async function deleteTablon(id) {
  const response = await fetch(`/api/deleteTablon?id=${id}`, {
    method: "DELETE",
    headers: {
      Authorization: token,
    },
  });
  return response.json();
}

// Función para añadir un mensaje a un tablón
async function addMessage(tablonId, message) {
  const response = await fetch(
    `/api/addMessage?tablon_id=${tablonId}&message=${encodeURIComponent(
      message
    )}`,
    {
      method: "POST",
    }
  );
  return response.json();
}

// Función para eliminar un mensaje
async function deleteMessage(tablonId, messageId) {
  const response = await fetch(
    `/api/deleteMessage?tablonId=${tablonId}&messageId=${messageId}`,
    {
      method: "DELETE",
      headers: {
        Authorization: token,
      },
    }
  );
  return response.json();
}

// Función para dar like a un mensaje
async function likeMessage(tablonId, messageId) {
  const response = await fetch(
    `/api/likeMessage?tablonId=${tablonId}&messageId=${messageId}`,
    {
      method: "POST",
    }
  );
  return response.json();
}

// Función para filtrar tablones por nombre
function filterTablonesByName(query) {
  return filteredTablones.filter(
    (tablon) =>
      tablon.name && tablon.name.toLowerCase().includes(query.toLowerCase())
  );
}

// Función para renderizar los tablones
function renderTablones(tablones) {
  const tablonesListElement = document.getElementById("tablonesList");
  tablonesListElement.innerHTML = "";

  if (!Array.isArray(tablones) || tablones.length === 0) {
    tablonesListElement.innerHTML =
      "<p>Buscando nodos y tablones disponibles.</p>";
    return;
  }

  tablones.forEach((tablon) => {
    const tablonElement = document.createElement("div");
    tablonElement.className = "tablon";
    tablonElement.innerHTML = `
                    <h3>${tablon.name} <small class="text-muted">${
      tablon.geo || ""
    }</small></h3>

                    <div class="messages mt-3">
                        ${tablon.messages
                          .map(
                            (message) => `
                            <div class="message">
                                <p>${message.content.message}</p>
                                <small class="text-muted">${new Date(
                                  message.timestamp
                                ).toLocaleString()}</small>
                                <button class="btn btn-sm btn-outline-primary" onclick="handleLikeMessage('${
                                  tablon.id
                                }', '${message.id}')">
                                    <i class="fas fa-eye"></i> ${
                                      message.content.likes
                                    }
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="handleDeleteMessage('${
                                  tablon.id
                                }', '${message.id}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        `
                          )
                          .join("")}
                    </div>
                    <button class="btn btn-sm btn-danger float-end" onclick="handleDeleteTablon('${
                      tablon.id
                    }')">
                        <i class="fas fa-trash"></i> Eliminar Tablón
                    </button><br>
                    <form onsubmit="handleAddMessage(event, '${
                      tablon.id
                    }')" class="mt-3">
                        <div class="input-group">
                            <input type="text" class="form-control" placeholder="Nuevo mensaje" required>
                            <button class="btn btn-outline-secondary" type="submit">Enviar</button>
                        </div>
                    </form>
                `;
    tablonesListElement.appendChild(tablonElement);
  });
}

// Manejadores de eventos
async function handleCreateTablon(event) {
  event.preventDefault();

  try {
    const name = document.getElementById("tablonName").value;
    const message = document.getElementById("tablonMessage").value;
    const geo = document.getElementById("tablonGeo").value || "";

    // Validar campos
    if (!name || !message) {
      alert("Por favor, completa los campos obligatorios");
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
        alert("Grupo creado correctamente");

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
    console.error("Error al crear el grupo:", error);
    alert(`Error al crear el grupo: ${error.message}`);
  }
}

async function handleDeleteTablon(id) {
  await deleteTablon(id);
  refreshTablones();
}

async function handleAddMessage(event, tablonId) {
  event.preventDefault();
  const message = event.target.querySelector("input").value;
  await addMessage(tablonId, message);
  refreshTablones();
}

async function handleDeleteMessage(tablonId, messageId) {
  await deleteMessage(tablonId, messageId);
  refreshTablones();
}

async function handleLikeMessage(tablonId, messageId) {
  await likeMessage(tablonId, messageId);
  refreshTablones();
}

// Función para refrescar la lista de tablones con paginación
// Añadir una variable para controlar si ya se está actualizando
let isRefreshing = false;
let autoRefreshEnabled = true;
let refreshIntervalId;
let currentRefreshInterval = 30000; // Intervalo por defecto de 30 segundos

// Función para refrescar la lista de tablones con paginación
async function refreshTablones() {
  if (isRefreshing || !autoRefreshEnabled) return; // Evita ejecutar si ya está refrescando o si está desactivado
  isRefreshing = true;
  const searchQuery = document.getElementById("searchInput").value;
  const allTablones = await getTablones();
  filteredTablones = searchQuery
    ? filterTablonesByName(searchQuery)
    : allTablones;
  const paginatedTablones = paginate(
    filteredTablones,
    currentPage,
    itemsPerPage
  );
  renderTablones(paginatedTablones);
  renderPagination(filteredTablones.length);
  isRefreshing = false;
}

// Función para iniciar la actualización automática
function startAutoRefresh() {
  refreshIntervalId = setInterval(refreshTablones, currentRefreshInterval);
}

// Función para detener la actualización automática
function stopAutoRefresh() {
  clearInterval(refreshIntervalId);
}

// Manejador para el toggle de auto actualización
document
  .getElementById("autoRefreshToggle")
  .addEventListener("change", function (event) {
    autoRefreshEnabled = event.target.checked;
    if (autoRefreshEnabled) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });

// Manejador para el cambio de intervalo
document
  .getElementById("refreshInterval")
  .addEventListener("change", function (event) {
    currentRefreshInterval = parseInt(event.target.value) * 1000; // Convertir a milisegundos
    if (autoRefreshEnabled) {
      stopAutoRefresh(); // Detener la anterior
      startAutoRefresh(); // Iniciar con el nuevo intervalo
    }
  });

// Inicialización
if (token) {
  document.getElementById("loginForm").style.display = "none";
  refreshTablones();
}

// Iniciar actualización automática por defecto
startAutoRefresh();

// Inicialización
if (token) {
  document.getElementById("loginForm").style.display = "none";
  refreshTablones();
}

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
//wpa
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

async function fetchRecibe() {
  try {
    const response = await fetch("http://127.0.0.1:8080/api/recibe", {
      method: "GET", // O 'POST' según sea necesario
      headers: {
        "Content-Type": "application/json",
        Authorization: token, // Si es necesario un token de autorización
      },
    });

    if (!response.ok) {
      throw new Error("Error en la solicitud a /api/recibe");
    }

    const data = await response.json();
    console.log("Datos recibidos:", data);

    // Seleccionar el contenedor
    const slidingTextContainer = document.getElementById(
      "slidingTextContainer"
    );
    slidingTextContainer.innerHTML = ""; // Limpiar cualquier contenido previo

    // Generar dinámicamente los items con texto deslizante
    data.forEach((item) => {
      const slidingText = `
                <div class="slidingTextItem">
                    <div class="slidingText">
                        <h5>${item.content.title}</h5>
                        <p>${item.content.message}</p>
                    </div>
                </div>
            `;
      slidingTextContainer.innerHTML += slidingText;
    });
  } catch (error) {
    console.error("Error en fetchRecibe:", error);
  }
}

//
document.addEventListener("DOMContentLoaded", () => {
  fetchRecibe(); // Llamar a la función cuando cargue la página
});

document
  .getElementById("createTablonForm")
  .addEventListener("submit", handleCreateTablon);
document
  .getElementById("searchInput")
  .addEventListener("input", refreshTablones);
refreshTablones(); // Inicializar la lista de tablones al cargar la página

// La configuración del formulario de carga de archivos se maneja en file-handler.js

// La función refreshReceivedFiles se encuentra en file-handler.js

// Función para borrar el token cada 1 hora
setInterval(() => {
  localStorage.removeItem("token");
  console.log("Token eliminado de localStorage");
}, 3600000); // 3600000 ms = 1 hora
