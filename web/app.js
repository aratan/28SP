// app.js

const API_URL = "http://localhost:8080/api";

// Función para crear un nuevo tablón
async function createTablon(event) {
  event.preventDefault();
  const form = event.target;
  const formData = new FormData(form);

  try {
    const response = await axios.post(`${API_URL}/createTablon`, null, {
      params: Object.fromEntries(formData),
    });
    console.log("Tablón creado:", response.data);
    await loadTablones();
    form.reset();
    showNotification("Tablón creado con éxito", "success");
  } catch (error) {
    console.error("Error al crear el tablón:", error);
    showNotification("Error al crear el tablón", "error");
  }
}

// Función para cargar los tablones
async function loadTablones() {
  try {
    const response = await axios.get(`${API_URL}/readTablon`);
    const tablones = response.data;
    const tablonesList = document.getElementById("tablonesList");
    tablonesList.innerHTML = "";

    tablones.forEach((tablon, index) => {
      const tablonElement = createTablonElement(tablon, index);
      tablonesList.appendChild(tablonElement);
    });
  } catch (error) {
    console.error("Error al cargar los tablones:", error);
    showNotification("Error al cargar los tablones", "error");
  }
}

// Función para crear el elemento HTML de un tablón
function createTablonElement(tablon, index) {
  const tablonDiv = document.createElement("div");
  tablonDiv.className = "bg-white shadow-md rounded-lg p-6 mb-4";
  tablonDiv.innerHTML = `
        <h3 class="text-xl font-semibold mb-2">${tablon.name}</h3>
        <p class="text-gray-600 mb-4">${
          tablon.geo ? `Ubicación: ${tablon.geo}` : "Sin ubicación"
        }</p>
        <div class="space-y-2 mb-4" id="messages-${tablon.id}">
            ${tablon.messages
              .map(
                (msg, msgIndex) => `
                <div class="border-t pt-2 flex justify-between items-center">
                    <div>
                        <p class="text-sm text-gray-800">${msg.content.message}</p>
                        <p class="text-xs text-gray-500">Likes: ${msg.content.likes}</p>
                        
                        
            
                    </div>
                    <button onclick="deleteMessage('${tablon.id}', ${msgIndex})" class="text-red-500 hover:text-red-700">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
                        </svg>
                    </button>
                </div>
            `
              )
              .join("")}
        </div>
        <div class="flex justify-between items-center mb-4">
            <button onclick="addLikeToTablon('${
              tablon.id
            }')" class="bg-green-500 hover:bg-green-700 text-white font-bold py-1 px-3 rounded text-sm">
                Me gusta (${tablon.likes})
            </button>
            <button onclick="deleteTablon(${index})" class="bg-red-500 hover:bg-red-700 text-white font-bold py-1 px-3 rounded text-sm">
                Eliminar Discusión
            </button>
        </div>
        <form onsubmit="addMessageToTablon(event, '${tablon.id}')" class="mt-4">
            <input type="text" name="message" placeholder="Añadir mensaje" required class="w-full px-3 py-2 border rounded-md">
            <button type="submit" class="mt-2 w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                Añadir Mensaje
            </button>
        </form>
    `;
  return tablonDiv;
}

// Función para añadir un "me gusta" a un mensaje
async function addLikeToMessage(messageIndex) {
  try {
    await axios.post(`${API_URL}/addLikeToMessage`, null, {
      params: { messageIndex: tablonId },
    });
    await loadTablones();
    showNotification("Like añadido al mensage", "success");
  } catch (error) {
    console.error("Error al añadir like al mensage:", error);
    showNotification("Error al añadir like al mensage", "error");
  }
}

// Función para añadir un "me gusta" a un tablón
async function addLikeToTablon(tablonId) {
  try {
    await axios.post(`${API_URL}/addLikeToTablon`, null, {
      params: { tablon_id: tablonId },
    });
    await loadTablones();
    showNotification("Like añadido al tablón", "success");
  } catch (error) {
    console.error("Error al añadir like al tablón:", error);
    showNotification("Error al añadir like al tablón", "error");
  }
}

// Función para eliminar un tablón
async function deleteTablon(index) {
  if (confirm("¿Estás seguro de que quieres eliminar este tablón?")) {
    try {
      await axios.delete(`${API_URL}/deleteTablonByIndex`, {
        params: { index },
      });
      await loadTablones();
      showNotification("Tablón eliminado con éxito", "success");
    } catch (error) {
      console.error("Error al eliminar el tablón:", error);
      showNotification("Error al eliminar el tablón", "error");
    }
  }
}

// Función para añadir un mensaje a un tablón
async function addMessageToTablon(event, tablonId) {
  event.preventDefault();
  const form = event.target;
  const message = form.message.value;

  try {
    await axios.post(`${API_URL}/addMessage`, null, {
      params: { tablon_id: tablonId, message },
    });
    await loadTablones();
    form.reset();
    showNotification("Mensaje añadido con éxito", "success");
  } catch (error) {
    console.error("Error al añadir mensaje al tablón:", error);
    showNotification("Error al añadir mensaje al tablón", "error");
  }
}

// Función para eliminar un mensaje
async function deleteMessage(tablonId, messageIndex) {
  if (confirm("¿Estás seguro de que quieres eliminar este mensaje?")) {
    try {
      await axios.delete(`${API_URL}/deleteMessageByIndex`, {
        params: { tablon_id: tablonId, index: messageIndex },
      });
      await loadTablones();
      showNotification("Mensaje eliminado con éxito", "success");
    } catch (error) {
      console.error("Error al eliminar el mensaje:", error);
      showNotification("Error al eliminar el mensaje", "error");
    }
  }
}

// Función para mostrar notificaciones
function showNotification(message, type) {
  const notification = document.createElement("div");
  notification.className = `fixed bottom-4 right-4 p-4 rounded-md text-white ${
    type === "success" ? "bg-green-500" : "bg-red-500"
  }`;
  notification.textContent = message;
  document.body.appendChild(notification);
  setTimeout(() => {
    notification.remove();
  }, 3000);
}

// Event listeners
document
  .getElementById("createTablonForm")
  .addEventListener("submit", createTablon);

// Cargar tablones al iniciar la aplicación
document.addEventListener("DOMContentLoaded", loadTablones);
