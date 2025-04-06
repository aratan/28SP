/**
 * Manejador para la función fetchRecibe
 * Este archivo contiene una implementación robusta de la función fetchRecibe
 */

// Función para obtener el token JWT del almacenamiento local
function getToken() {
  return localStorage.getItem('token');
}

/**
 * Función para obtener datos de la API
 */
async function fetchRecibe() {
  try {
    // Verificar si hay token
    const token = getToken();
    if (!token) {
      console.log('No hay token disponible. Inicia sesión primero.');
      return;
    }
    
    // Seleccionar el contenedor
    const slidingTextContainer = document.getElementById("slidingTextContainer");
    if (!slidingTextContainer) {
      console.error('No se encontró el contenedor slidingTextContainer');
      return;
    }
    
    // Mostrar indicador de carga
    slidingTextContainer.innerHTML = '<div class="text-center p-3"><i class="fas fa-spinner fa-spin me-2"></i> Cargando datos...</div>';
    
    try {
      const response = await fetch("/api/recibe", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Authorization": token,
        },
      });

      if (!response.ok) {
        throw new Error(`Error en la solicitud: ${response.status} ${response.statusText}`);
      }
      
      // Leer el texto de la respuesta
      const text = await response.text();
      if (!text || text.trim() === '') {
        slidingTextContainer.innerHTML = '<div class="alert alert-info">No hay datos disponibles</div>';
        return;
      }
      
      // Intentar parsear el JSON
      let data;
      try {
        data = JSON.parse(text);
      } catch (parseError) {
        console.error('Error al parsear JSON:', parseError, 'Texto recibido:', text);
        slidingTextContainer.innerHTML = '<div class="alert alert-danger">Error al procesar los datos recibidos</div>';
        return;
      }
      
      // Verificar que data es un array
      if (!data || !Array.isArray(data) || data.length === 0) {
        slidingTextContainer.innerHTML = '<div class="alert alert-info">No hay datos disponibles</div>';
        return;
      }
      
      console.log("Datos recibidos:", data);
      
      // Limpiar el contenedor
      slidingTextContainer.innerHTML = '';

      // Generar dinámicamente los items con texto deslizante
      data.forEach((item) => {
        try {
          // Verificar que item y sus propiedades existen
          if (!item || !item.content) {
            console.warn('Item inválido:', item);
            return;
          }
          
          const title = item.content && item.content.title ? item.content.title : 'Sin título';
          const message = item.content && item.content.message ? item.content.message : 'Sin mensaje';
          
          const slidingText = `
            <div class="card mb-3">
              <div class="card-body">
                <h5 class="card-title">${title}</h5>
                <p class="card-text">${message}</p>
              </div>
            </div>
          `;
          slidingTextContainer.innerHTML += slidingText;
        } catch (itemError) {
          console.error('Error al procesar item:', itemError, item);
        }
      });
    } catch (fetchError) {
      console.error("Error al obtener datos:", fetchError);
      slidingTextContainer.innerHTML = `<div class="alert alert-danger">Error al obtener datos: ${fetchError.message}</div>`;
    }
  } catch (error) {
    console.error("Error general en fetchRecibe:", error);
  }
}

// Inicializar cuando el DOM esté listo
document.addEventListener("DOMContentLoaded", () => {
  // Buscar el botón que llama a fetchRecibe
  const fetchButton = document.querySelector('button[onclick="fetchRecibe()"]');
  if (fetchButton) {
    // Reemplazar el manejador de eventos onclick
    fetchButton.onclick = function(event) {
      event.preventDefault();
      fetchRecibe();
    };
  }
  
  // También podemos llamar a fetchRecibe al cargar la página
  // fetchRecibe();
});
