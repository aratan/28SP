// Funciones para manejar la carga y descarga de archivos

// Obtener el token de autenticación
const getToken = () => localStorage.getItem("token");

// Función para enviar un archivo
async function uploadFile(file) {
  const token = getToken();
  if (!token) {
    alert("Debes iniciar sesión para enviar archivos");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch("/api/sendBinary", {
      method: "POST",
      headers: {
        Authorization: token,
      },
      body: formData,
    });

    if (response.ok) {
      const result = await response.json();
      return result;
    } else {
      throw new Error("Error al enviar el archivo");
    }
  } catch (error) {
    console.error("Error:", error);
    throw error;
  }
}

// Función para obtener la lista de archivos recibidos
async function getReceivedFiles() {
  const token = getToken();
  if (!token) {
    console.log("No hay token disponible");
    return [];
  }

  try {
    const response = await fetch("/api/recibe", {
      headers: {
        Authorization: token,
      },
    });

    if (response.ok) {
      const text = await response.text();
      if (!text || text.trim() === "") {
        console.log("Respuesta vacía del servidor");
        return [];
      }

      try {
        const messages = JSON.parse(text);
        if (!Array.isArray(messages)) {
          console.log("La respuesta no es un array:", messages);
          return [];
        }
        return messages.filter(
          (msg) => msg && msg.Action === "binary_transfer"
        );
      } catch (parseError) {
        console.error(
          "Error al parsear JSON:",
          parseError,
          "Texto recibido:",
          text
        );
        return [];
      }
    } else {
      console.error(
        "Error en la respuesta:",
        response.status,
        response.statusText
      );
      return [];
    }
  } catch (error) {
    console.error("Error en la petición:", error);
    return [];
  }
}

// Función para actualizar la lista de archivos recibidos en la interfaz
async function refreshReceivedFiles() {
  try {
    const receivedFilesContainer = document.getElementById("receivedFiles");
    if (!receivedFilesContainer) {
      console.error("No se encontró el contenedor de archivos recibidos");
      return;
    }

    receivedFilesContainer.innerHTML = "";

    const fileMessages = await getReceivedFiles();

    // Siempre mostrar un mensaje cuando no hay archivos
    if (!fileMessages || fileMessages.length === 0) {
      receivedFilesContainer.innerHTML =
        '<p class="text-muted">No hay archivos recibidos</p>';
      return;
    }

    fileMessages.forEach((file) => {
      try {
        const fileItem = document.createElement("a");
        fileItem.className = "list-group-item list-group-item-action";

        // Verificar que los datos necesarios existen
        const fileId = file.ID || "unknown";
        const fileName = file.FileName || "Archivo sin nombre";

        fileItem.href = `received_files/${fileId}_${fileName}`;
        fileItem.target = "_blank";

        // Verificar que los datos necesarios existen
        const timestamp = file.Timestamp
          ? new Date(file.Timestamp).toLocaleString()
          : "Fecha desconocida";
        const username =
          file.From && file.From.Username
            ? file.From.Username
            : "Usuario desconocido";

        fileItem.innerHTML = `
          <div class="d-flex w-100 justify-content-between">
            <h5 class="mb-1">${fileName}</h5>
            <small>${timestamp}</small>
          </div>
          <p class="mb-1">Enviado por: ${username}</p>
        `;
        receivedFilesContainer.appendChild(fileItem);
      } catch (itemError) {
        console.error("Error al procesar archivo:", itemError, file);
      }
    });
  } catch (error) {
    console.error("Error al actualizar la lista de archivos:", error);

    // Mostrar mensaje de error en la interfaz
    const receivedFilesContainer = document.getElementById("receivedFiles");
    if (receivedFilesContainer) {
      receivedFilesContainer.innerHTML =
        '<p class="text-danger">Error al cargar los archivos recibidos</p>';
    }
  }
}

// Configurar el formulario de carga de archivos cuando el DOM esté listo
document.addEventListener("DOMContentLoaded", function () {
  const fileUploadForm = document.getElementById("fileUploadForm");
  if (fileUploadForm) {
    fileUploadForm.addEventListener("submit", async function (e) {
      e.preventDefault();

      const fileInput = document.getElementById("fileInput");
      if (!fileInput.files || fileInput.files.length === 0) {
        alert("Por favor, selecciona un archivo");
        return;
      }

      const file = fileInput.files[0];

      try {
        const result = await uploadFile(file);
        alert(
          `Archivo enviado correctamente. ID del mensaje: ${result.messageId}`
        );
        fileInput.value = ""; // Limpiar el input
        refreshReceivedFiles();
      } catch (error) {
        alert("Error al enviar el archivo");
      }
    });
  }

  // Actualizar la lista de archivos recibidos al cargar la página
  if (getToken()) {
    refreshReceivedFiles();
  }
});
