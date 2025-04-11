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
  const receivedFilesContainer = document.getElementById("receivedFiles");
  if (!receivedFilesContainer) {
    console.error("No se encontró el contenedor de archivos recibidos");
    return;
  }

  // Mostrar indicador de carga
  receivedFilesContainer.innerHTML =
    '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Cargando archivos...</div>';

  try {
    const files = await getReceivedFiles();

    if (!files || files.length === 0) {
      receivedFilesContainer.innerHTML =
        '<div class="alert alert-info">No hay archivos recibidos</div>';
      return;
    }

    // Crear el acordeón para la lista desplegable
    const accordionId = "filesAccordion";
    let accordionHTML = `<div class="accordion" id="${accordionId}">`;

    // Agrupar archivos por fecha (usando el día)
    const filesByDate = {};
    files.forEach((file) => {
      const date = new Date(file.Timestamp || Date.now());
      const dateKey = date.toLocaleDateString();

      if (!filesByDate[dateKey]) {
        filesByDate[dateKey] = [];
      }
      filesByDate[dateKey].push(file);
    });

    // Crear un elemento de acordeón para cada fecha
    Object.keys(filesByDate).forEach((dateKey, index) => {
      const dateFiles = filesByDate[dateKey];
      const headingId = `heading${index}`;
      const collapseId = `collapse${index}`;

      accordionHTML += `
        <div class="accordion-item">
          <h2 class="accordion-header" id="${headingId}">
            <button class="accordion-button ${
              index === 0 ? "" : "collapsed"
            }" type="button" data-bs-toggle="collapse"
                    data-bs-target="#${collapseId}" aria-expanded="${
        index === 0 ? "true" : "false"
      }" aria-controls="${collapseId}">
              <i class="fas fa-calendar-day me-2"></i> ${dateKey} <span class="badge bg-primary ms-2">${
        dateFiles.length
      }</span>
            </button>
          </h2>
          <div id="${collapseId}" class="accordion-collapse collapse ${
        index === 0 ? "show" : ""
      }"
               aria-labelledby="${headingId}" data-bs-parent="#${accordionId}">
            <div class="accordion-body p-0">
              <ul class="list-group list-group-flush">
      `;

      // Agregar cada archivo a la lista
      dateFiles.forEach((file) => {
        const fileName = file.FileName || "Archivo sin nombre";
        const fileTime = file.Timestamp
          ? new Date(file.Timestamp).toLocaleTimeString()
          : "Hora desconocida";
        const fileId = file.ID || "unknown";

        accordionHTML += `
          <li class="list-group-item d-flex justify-content-between align-items-center">
            <div>
              <i class="fas fa-file me-2"></i>
              <span>${fileName}</span>
              <small class="text-muted ms-2">${fileTime}</small>
            </div>
            <div>
              <a href="/received_files/${fileId}_${fileName}" class="btn btn-sm btn-outline-primary" download>
                <i class="fas fa-download"></i>
              </a>
            </div>
          </li>
        `;
      });

      accordionHTML += `
              </ul>
            </div>
          </div>
        </div>
      `;
    });

    accordionHTML += "</div>";
    receivedFilesContainer.innerHTML = accordionHTML;
  } catch (error) {
    console.error("Error al actualizar la lista de archivos:", error);
    receivedFilesContainer.innerHTML = `<div class="alert alert-danger">Error al cargar archivos: ${error.message}</div>`;
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
