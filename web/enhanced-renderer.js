/**
 * Enhanced Renderer for P2P Message Board
 * This file enhances the visual presentation of the existing functionality
 */

// Override the existing renderTablones function to use our enhanced UI
window.renderTablones = function(tablones) {
    const tablonesContainer = document.getElementById('tablonesList');
    tablonesContainer.innerHTML = '';
    
    if (!tablones || tablones.length === 0) {
        tablonesContainer.innerHTML = '<div class="alert alert-info"><i class="fas fa-info-circle me-2"></i>No hay grupos disponibles. ¡Crea el primero!</div>';
        return;
    }
    
    tablones.forEach(tablon => {
        const card = document.createElement('div');
        card.className = 'card mb-4';
        
        // Get the first message (initial message)
        const initialMessage = tablon.Messages && tablon.Messages.length > 0 ? tablon.Messages[0] : null;
        
        // Format date
        let timestamp = 'Fecha desconocida';
        if (initialMessage && initialMessage.Timestamp) {
            timestamp = new Date(initialMessage.Timestamp).toLocaleString();
        }
        
        // Get creator
        let creator = 'Anónimo';
        if (initialMessage && initialMessage.From && initialMessage.From.Username) {
            creator = initialMessage.From.Username;
        }
        
        // Get message
        let message = 'Sin mensaje';
        if (initialMessage && initialMessage.Content && initialMessage.Content.Message) {
            message = initialMessage.Content.Message;
        }
        
        // Create card header
        const cardHeader = document.createElement('div');
        cardHeader.className = 'card-header bg-primary text-white d-flex justify-content-between align-items-center';
        cardHeader.innerHTML = `
            <h5 class="card-title mb-0">${tablon.Name}</h5>
            <span class="badge bg-light text-dark">${tablon.Messages ? tablon.Messages.length : 0} mensajes</span>
        `;
        
        // Create card body
        const cardBody = document.createElement('div');
        cardBody.className = 'card-body';
        
        // Add meta information
        const metaInfo = document.createElement('div');
        metaInfo.className = 'd-flex justify-content-between text-muted mb-3';
        metaInfo.innerHTML = `
            <span><i class="fas fa-user me-1"></i> ${creator}</span>
            <span><i class="fas fa-clock me-1"></i> ${timestamp}</span>
            ${tablon.Geo ? `<span><i class="fas fa-map-marker-alt me-1"></i> ${tablon.Geo}</span>` : ''}
        `;
        
        // Add message content
        const messageContent = document.createElement('div');
        messageContent.className = 'mb-3';
        messageContent.textContent = message;
        
        // Add action buttons
        const actionButtons = document.createElement('div');
        actionButtons.className = 'd-flex gap-2 mb-3';
        actionButtons.innerHTML = `
            <button class="btn btn-sm btn-primary" onclick="handleAddMessage(event, '${tablon.ID}')">
                <i class="fas fa-comment me-1"></i> Enviar Mensaje
            </button>
            <button class="btn btn-sm btn-danger" onclick="handleDeleteTablon('${tablon.ID}')">
                <i class="fas fa-trash me-1"></i> Eliminar Grupo
            </button>
        `;
        
        // Add messages list if there are more than the initial message
        let messagesList = '';
        if (tablon.Messages && tablon.Messages.length > 1) {
            messagesList = '<h6 class="mt-4 mb-3"><i class="fas fa-comments me-2"></i>Mensajes</h6>';
            
            tablon.Messages.slice(1).forEach(msg => {
                // Format message date
                let msgTimestamp = 'Fecha desconocida';
                if (msg.Timestamp) {
                    msgTimestamp = new Date(msg.Timestamp).toLocaleString();
                }
                
                // Get message author
                let author = 'Anónimo';
                if (msg.From && msg.From.Username) {
                    author = msg.From.Username;
                }
                
                // Get message content
                let content = 'Sin contenido';
                if (msg.Content && msg.Content.Message) {
                    content = msg.Content.Message;
                }
                
                // Get likes count
                let likes = 0;
                if (msg.Content && msg.Content.Likes) {
                    likes = msg.Content.Likes;
                }
                
                messagesList += `
                    <div class="card mb-2">
                        <div class="card-body py-2 px-3">
                            <div class="d-flex justify-content-between">
                                <span class="fw-bold">${author}</span>
                                <small class="text-muted">${msgTimestamp}</small>
                            </div>
                            <p class="mb-2">${content}</p>
                            <div class="d-flex justify-content-between">
                                <button class="btn btn-sm btn-outline-primary" onclick="handleLikeMessage('${tablon.ID}', '${msg.ID}')">
                                    <i class="fas fa-thumbs-up me-1"></i> ${likes}
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="handleDeleteMessage('${tablon.ID}', '${msg.ID}')">
                                    <i class="fas fa-trash me-1"></i> Eliminar
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            });
        }
        
        // Add message form
        const messageForm = document.createElement('form');
        messageForm.className = 'mt-3';
        messageForm.innerHTML = `
            <div class="input-group">
                <input type="text" class="form-control" placeholder="Nuevo mensaje" required>
                <button class="btn btn-outline-primary" type="submit">
                    <i class="fas fa-paper-plane me-1"></i> Enviar
                </button>
            </div>
        `;
        messageForm.onsubmit = function(e) {
            e.preventDefault();
            handleAddMessage(e, tablon.ID);
        };
        
        // Append all elements to card body
        cardBody.appendChild(metaInfo);
        cardBody.appendChild(messageContent);
        cardBody.appendChild(actionButtons);
        cardBody.innerHTML += messagesList;
        cardBody.appendChild(messageForm);
        
        // Append header and body to card
        card.appendChild(cardHeader);
        card.appendChild(cardBody);
        
        // Add card to container
        tablonesContainer.appendChild(card);
    });
};
