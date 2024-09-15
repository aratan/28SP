let tablones = [];
let currentPage = 1;
const pageSize = 5; // Número de tablones por página

// Función para crear un tablón
async function createTablon(name, message, geo) {
  const response = await fetch(
    `/api/createTablon?name=${encodeURIComponent(
      name
    )}&mensaje=${encodeURIComponent(message)}&geo=${encodeURIComponent(geo)}`,
    {
      method: "POST",
    }
  );
  return response.json();
}

// Función para obtener todos los tablones
async function getTablones() {
  const response = await fetch("/api/readTablon");
  return response.json();
}

// Función para eliminar un tablón
async function deleteTablon(id) {
  const response = await fetch(`/api/deleteTablon?id=${id}`, {
    method: "DELETE",
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

// Función para renderizar los tablones
function renderTablones(filteredTablones) {
  const tablonesListElement = document.getElementById("tablonesList");
  tablonesListElement.innerHTML = "";

  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedTablones = filteredTablones.slice(startIndex, endIndex);

  paginatedTablones.forEach((tablon) => {
    const tablonElement = document.createElement("div");
    tablonElement.className = "tablon";
    tablonElement.innerHTML = `
            <h3>${tablon.name} <small class="text-muted">${
      tablon.geo || ""
    }</small></h3>
            <button class="btn btn-sm btn-danger float-end" onclick="handleDeleteTablon('${
              tablon.id
            }')">
                <i class="fas fa-trash"></i> Eliminar Tablón
            </button>
            <div class="messages mt-3">
                ${tablon.messages
                  .map(
                    (message) => `
                    <div class="message ${
                      message.sender === "yo" ? "sender" : "receiver"
                    }">
                        <p>${message.content.message}</p>
                        <small class="text-muted">${new Date(
                          message.timestamp
                        ).toLocaleString()}</small>
                        <div class="message-buttons">
                            <button class="btn btn-sm btn-outline-primary" onclick="handleLikeMessage('${
                              tablon.id
                            }', '${message.id}')">
                                <i class="fas fa-thumbs-up"></i> ${
                                  message.content.likes
                                }
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="handleDeleteMessage('${
                              tablon.id
                            }', '${message.id}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                `
                  )
                  .join("")}
            </div>
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

  // Actualiza la paginación
  document
    .getElementById("prevPage")
    .classList.toggle("disabled", currentPage === 1);
  document
    .getElementById("nextPage")
    .classList.toggle("disabled", endIndex >= filteredTablones.length);
}

// Función para manejar la creación de un tablón
async function handleCreateTablon(event) {
  event.preventDefault();
  const name = document.getElementById("tablonName").value;
  const message = document.getElementById("tablonMessage").value;
  const geo = document.getElementById("tablonGeo").value;

  // Primero, crea el tablón
  const newTablon = await createTablon(name, message, geo);

  // Ahora, añade el mensaje inicial al tablón recién creado
  if (newTablon && newTablon.id) {
    await addMessage(newTablon.id, message);
  }

  // Vuelve a cargar los tablones
  await loadTablones();
}

// Funciones de paginación
function handleNextPage(event) {
  event.preventDefault();
  currentPage++;
  handleSearch(); // Usamos el buscador para filtrar y paginar
}

function handlePrevPage(event) {
  event.preventDefault();
  if (currentPage > 1) currentPage--;
  handleSearch();
}

// Función para manejar el filtrado por búsqueda
function handleSearch() {
  const searchQuery = document
    .getElementById("searchInput")
    .value.toLowerCase();
  const filteredTablones = tablones.filter(
    (tablon) =>
      tablon.name.toLowerCase().includes(searchQuery) ||
      (tablon.geo && tablon.geo.toLowerCase().includes(searchQuery))
  );
  renderTablones(filteredTablones);
}

function clearSearch() {
  document.getElementById("searchInput").value = "";
  handleSearch();
}

// Función para cargar los tablones desde el servidor
async function loadTablones() {
  tablones = await getTablones();
  handleSearch(); // Renderiza con la búsqueda aplicada
}

// Inicialización
document
  .getElementById("createTablonForm")
  .addEventListener("submit", handleCreateTablon);
loadTablones();
