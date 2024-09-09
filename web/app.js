const API_BASE_URL = 'http://localhost:8080/api';
let token = localStorage.getItem('token');

// DOM Elements
const loginForm = document.getElementById('login-form');
const loginUsername = document.getElementById('login-username');
const loginPassword = document.getElementById('login-password');
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const content = document.getElementById('content');
const usernameSpan = document.getElementById('username');
const createTablonBtn = document.getElementById('create-tablon-btn');
const tablonName = document.getElementById('tablon-name');
const tablonMessage = document.getElementById('tablon-message');
const tablonGeo = document.getElementById('tablon-geo');
const tablonesList = document.getElementById('tablones-list');

// Event Listeners
loginBtn.addEventListener('click', login);
logoutBtn.addEventListener('click', logout);
createTablonBtn.addEventListener('click', createTablon);

// Check if user is logged in
if (token) {
    showContent();
} else {
    showLoginForm();
}

async function login() {
    const username = loginUsername.value;
    const password = loginPassword.value;

    try {
        const response = await fetch(`${API_BASE_URL}/generateToken?username=${encodeURIComponent(username)}`, {
            method: 'GET',
        });

        if (response.ok) {
            const data = await response.json();
            token = data.token;
            localStorage.setItem('token', token);
            showContent();
        } else {
            alert('Login failed. Please try again.');
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('An error occurred. Please try again.');
    }
}

function logout() {
    token = null;
    localStorage.removeItem('token');
    showLoginForm();
}

function showLoginForm() {
    loginForm.style.display = 'block';
    content.style.display = 'none';
    logoutBtn.style.display = 'none';
    usernameSpan.textContent = '';
}

function showContent() {
    loginForm.style.display = 'none';
    content.style.display = 'block';
    logoutBtn.style.display = 'inline';
    usernameSpan.textContent = 'Logged in';
    fetchTablones();
}

async function createTablon() {
    const name = tablonName.value;
    const message = tablonMessage.value;
    const geo = tablonGeo.value;

    try {
        const response = await fetch(`${API_BASE_URL}/createTablon?name=${encodeURIComponent(name)}&mensaje=${encodeURIComponent(message)}&geo=${encodeURIComponent(geo)}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (response.ok) {
            tablonName.value = '';
            tablonMessage.value = '';
            tablonGeo.value = '';
            fetchTablones();
        } else {
            alert('Failed to create tablon. Please try again.');
        }
    } catch (error) {
        console.error('Create tablon error:', error);
        alert('An error occurred. Please try again.');
    }
}

async function fetchTablones() {
    try {
        const response = await fetch(`${API_BASE_URL}/readTablon`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (response.ok) {
            const tablones = await response.json();
            displayTablones(tablones);
        } else {
            alert('Failed to fetch tablones. Please try again.');
        }
    } catch (error) {
        console.error('Fetch tablones error:', error);
        alert('An error occurred. Please try again.');
    }
}

function displayTablones(tablones) {
    tablonesList.innerHTML = '';
    tablones.forEach((tablon) => {
        const tablonElement = document.createElement('div');
        tablonElement.className = 'tablon';
        tablonElement.innerHTML = `
            <h3>${tablon.name}</h3>
            <p>Geo: ${tablon.geo}</p>
            <button class="delete-btn" onclick="deleteTablon('${tablon.id}')">Delete Tablon</button>
            <div class="messages">
                ${tablon.messages.map((message) => `
                    <div class="message">
                        <p>${message.content.message}</p>
                        <div class="message-actions">
                            <button class="like-btn" onclick="likeMessage('${tablon.id}', '${message.id}')">
                                Like (${message.content.likes})
                            </button>
                            <button class="delete-btn" onclick="deleteMessage('${tablon.id}', '${message.id}')">
                                Delete Message
                            </button>
                        </div>
                    </div>
                `).join('')}
            </div>
            <div class="new-message-form">
                <input type="text" id="new-message-${tablon.id}" placeholder="New message">
                <button onclick="sendMessage('${tablon.id}')">Send</button>
            </div>
        `;
        tablonesList.appendChild(tablonElement);
    });
}

async function deleteTablon(tablonId) {
    try {
        const response = await fetch(`${API_BASE_URL}/deleteTablon?id=${tablonId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (response.ok) {
            fetchTablones();
        } else {
            alert('Failed to delete tablon. Please try again.');
        }
    } catch (error) {
        console.error('Delete tablon error:', error);
        alert('An error occurred. Please try again.');
    }
}

async function deleteMessage(tablonId, messageId) {
    try {
        const response = await fetch(`${API_BASE_URL}/deleteMessage?tablonId=${tablonId}&messageId=${messageId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (response.ok) {
            fetchTablones();
        } else {
            alert('Failed to delete message. Please try again.');
        }
    } catch (error) {
        console.error('Delete message error:', error);
        alert('An error occurred. Please try again.');
    }
}

async function likeMessage(tablonId, messageId) {
    try {
        const response = await fetch(`${API_BASE_URL}/likeMessage?tablonId=${tablonId}&messageId=${messageId}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (response.ok) {
            fetchTablones();
        } else {
            alert('Failed to like message. Please try again.');
        }
    } catch (error) {
        console.error('Like message error:', error);
        alert('An error occurred. Please try again.');
    }
}

async function sendMessage(tablonId) {
    const messageInput = document.getElementById(`new-message-${tablonId}`);
    const message = messageInput.value;

    if (!message) {
        alert('Please enter a message.');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/addMessage?tablon_id=${tablonId}&message=${encodeURIComponent(message)}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (response.ok) {
            messageInput.value = '';
            fetchTablones();
        } else {
            alert('Failed to send message. Please try again.');
        }
    } catch (error) {
        console.error('Send message error:', error);
        alert('An error occurred. Please try again.');
    }
}