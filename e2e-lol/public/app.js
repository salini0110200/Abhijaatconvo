
const API_URL = window.location.origin;

let currentUser = null;
let token = null;
let keyPair = null;

// Crypto utilities using Web Crypto API
async function generateKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

async function importPublicKey(keyData) {
    const binaryKey = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));
    return await window.crypto.subtle.importKey(
        "spki",
        binaryKey,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );
}

async function encryptMessage(message, publicKey) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        data
    );
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptMessage(ciphertext, privateKey) {
    try {
        const binaryCipher = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            binaryCipher
        );
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    } catch (e) {
        return "[Unable to decrypt message]";
    }
}

// UI utilities
function showStatus(message, isError = false) {
    const status = document.getElementById('status');
    status.textContent = message;
    status.className = `status ${isError ? 'error' : 'success'}`;
    setTimeout(() => {
        status.className = 'status';
    }, 3000);
}

function showAuthSection() {
    document.getElementById('auth-section').classList.remove('hidden');
    document.getElementById('app-section').classList.add('hidden');
}

function showAppSection() {
    document.getElementById('auth-section').classList.add('hidden');
    document.getElementById('app-section').classList.remove('hidden');
    document.getElementById('current-user').textContent = currentUser;
}

// API calls
async function register(username, password) {
    keyPair = await generateKeyPair();
    const publicKey = await exportPublicKey(keyPair.publicKey);
    
    const response = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, publicKey })
    });
    
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Registration failed');
    
    return data;
}

async function login(username, password) {
    const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Login failed');
    
    // Note: In a real app, you'd need to store the private key securely
    // For now, generate a new key pair and update the public key on server
    keyPair = await generateKeyPair();
    const publicKey = await exportPublicKey(keyPair.publicKey);
    
    // Update public key on server
    await fetch(`${API_URL}/me/public-key`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${data.token}`
        },
        body: JSON.stringify({ publicKey })
    });
    
    return data;
}

async function getPublicKey(username) {
    const response = await fetch(`${API_URL}/keys/${username}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'User not found');
    return data.publicKey;
}

async function sendMessage(to, message) {
    try {
        const recipientPublicKey = await getPublicKey(to);
        const importedKey = await importPublicKey(recipientPublicKey);
        const ciphertext = await encryptMessage(message, importedKey);
        const nonce = btoa(Math.random().toString());
        
        const response = await fetch(`${API_URL}/send`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ to, ciphertext, nonce })
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Failed to send message');
        return data;
    } catch (error) {
        console.error('Send message error:', error);
        throw error;
    }
}

async function getMessages() {
    const response = await fetch(`${API_URL}/messages`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Failed to fetch messages');
    return data.messages;
}

async function displayMessages() {
    const container = document.getElementById('messages-container');
    
    try {
        const messages = await getMessages();
        
        if (messages.length === 0) {
            container.innerHTML = '<p class="empty-state">No messages yet</p>';
            return;
        }
        
        container.innerHTML = '';
        
        for (const msg of messages) {
            const decrypted = await decryptMessage(msg.ciphertext, keyPair.privateKey);
            const messageEl = document.createElement('div');
            messageEl.className = 'message-card';
            messageEl.innerHTML = `
                <div class="message-header">
                    <span class="message-from">From: ${msg.from}</span>
                    <span class="message-time">${new Date(msg.ts).toLocaleString()}</span>
                </div>
                <div class="message-body">${escapeHtml(decrypted)}</div>
            `;
            container.appendChild(messageEl);
        }
    } catch (error) {
        showStatus(error.message, true);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`${btn.dataset.tab}-tab`).classList.add('active');
        });
    });
    
    // Register form
    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;
        
        try {
            const data = await register(username, password);
            token = data.token;
            currentUser = username;
            showAppSection();
            showStatus('Registration successful!');
            displayMessages();
        } catch (error) {
            showStatus(error.message, true);
        }
    });
    
    // Login form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        
        try {
            const data = await login(username, password);
            token = data.token;
            currentUser = username;
            showAppSection();
            showStatus('Login successful!');
            displayMessages();
        } catch (error) {
            showStatus(error.message, true);
        }
    });
    
    // Send message form
    document.getElementById('send-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const recipient = document.getElementById('recipient').value;
        const message = document.getElementById('message').value;
        const submitBtn = e.target.querySelector('button[type="submit"]');
        
        try {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Sending...';
            await sendMessage(recipient, message);
            showStatus('Message sent successfully!');
            document.getElementById('message').value = '';
            displayMessages();
        } catch (error) {
            console.error('Error sending message:', error);
            showStatus(error.message, true);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Send Encrypted';
        }
    });
    
    // Logout
    document.getElementById('logout-btn').addEventListener('click', () => {
        currentUser = null;
        token = null;
        keyPair = null;
        showAuthSection();
        showStatus('Logged out successfully!');
    });
    
    // Refresh messages
    document.getElementById('refresh-btn').addEventListener('click', () => {
        displayMessages();
        showStatus('Messages refreshed!');
    });
});
