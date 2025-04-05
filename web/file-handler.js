// Funciones para manejar la carga y descarga de archivos

// Obtener el token de autenticación
const getToken = () => localStorage.getItem('token');

// Función para enviar un archivo
async function uploadFile(file) {
    const token = getToken();
    if (!token) {
        alert('Debes iniciar sesión para enviar archivos');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/sendBinary', {
            method: 'POST',
            headers: {
                'Authorization': token
            },
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            return result;
        } else {
            throw new Error('Error al enviar el archivo');
        }
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Función para obtener la lista de archivos recibidos
async function getReceivedFiles() {
    const token = getToken();
    if (!token) {
        return [];
    }

    try {
        const response = await fetch('/api/recibe', {
            headers: {
                'Authorization': token
            }
        });

        if (response.ok) {
            const messages = await response.json();
            return messages.filter(msg => msg.Action === 'binary_transfer');
        } else {
            throw new Error('Error al obtener archivos recibidos');
        }
    } catch (error) {
        console.error('Error:', error);
        return [];
    }
}

// Función para actualizar la lista de archivos recibidos en la interfaz
async function refreshReceivedFiles() {
    try {
        const fileMessages = await getReceivedFiles();
        const receivedFilesContainer = document.getElementById('receivedFiles');
        receivedFilesContainer.innerHTML = '';

        if (fileMessages.length === 0) {
            receivedFilesContainer.innerHTML = '<p class="text-muted">No hay archivos recibidos</p>';
            return;
        }

        fileMessages.forEach(file => {
            const fileItem = document.createElement('a');
            fileItem.className = 'list-group-item list-group-item-action';
            fileItem.href = `received_files/${file.ID}_${file.FileName}`;
            fileItem.target = '_blank';
            fileItem.innerHTML = `
                <div class="d-flex w-100 justify-content-between">
                    <h5 class="mb-1">${file.FileName}</h5>
                    <small>${new Date(file.Timestamp).toLocaleString()}</small>
                </div>
                <p class="mb-1">Enviado por: ${file.From.Username}</p>
            `;
            receivedFilesContainer.appendChild(fileItem);
        });
    } catch (error) {
        console.error('Error:', error);
    }
}

// Configurar el formulario de carga de archivos cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    const fileUploadForm = document.getElementById('fileUploadForm');
    if (fileUploadForm) {
        fileUploadForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('fileInput');
            if (!fileInput.files || fileInput.files.length === 0) {
                alert('Por favor, selecciona un archivo');
                return;
            }
            
            const file = fileInput.files[0];
            
            try {
                const result = await uploadFile(file);
                alert(`Archivo enviado correctamente. ID del mensaje: ${result.messageId}`);
                fileInput.value = ''; // Limpiar el input
                refreshReceivedFiles();
            } catch (error) {
                alert('Error al enviar el archivo');
            }
        });
    }
    
    // Actualizar la lista de archivos recibidos al cargar la página
    if (getToken()) {
        refreshReceivedFiles();
    }
});
