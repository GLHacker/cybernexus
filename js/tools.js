/* 
   CYBERNEXUS TOOLS ENGINE
   Autor: GLHacker
   Versión: 2.0 (Functional)
*/

// ==========================================
// 1. Password Generator
// ==========================================
function generatePassword() {
    const length = document.getElementById('pwd-length').value;
    const includeUpper = document.getElementById('pwd-upper').checked;
    const includeLower = document.getElementById('pwd-lower').checked;
    const includeNumbers = document.getElementById('pwd-numbers').checked;
    const includeSymbols = document.getElementById('pwd-symbols').checked;

    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+~`|}{[]:;?><,./-=";

    let chars = "";
    if (includeUpper) chars += upper;
    if (includeLower) chars += lower;
    if (includeNumbers) chars += numbers;
    if (includeSymbols) chars += symbols;

    if (chars === "") {
        alert("¡Selecciona al menos un tipo de caracter!");
        return;
    }

    let password = "";
    for (let i = 0; i < length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    document.getElementById('pwd-output').value = password;
    document.getElementById('pwd-length-val').innerText = length;
}

// Slider listener
document.getElementById('pwd-length').addEventListener('input', function() {
    document.getElementById('pwd-length-val').innerText = this.value;
});

// ==========================================
// 2. Hash Generator (SHA-256 via Web Crypto API)
// ==========================================
async function generateHash() {
    const text = document.getElementById('hash-input').value;
    const type = document.getElementById('hash-type').value; // sha1, sha256, sha512
    
    if(!text) return;

    // Convert string to buffer
    const msgBuffer = new TextEncoder().encode(text);

    // Hash the buffer (SHA-1 is deprecated but requested, using SHA-256 map)
    // WebCrypto supporta: SHA-1, SHA-256, SHA-384, SHA-512
    let algo = "SHA-256";
    if(type === "sha1") algo = "SHA-1";
    if(type === "sha512") algo = "SHA-512";

    const hashBuffer = await crypto.subtle.digest(algo, msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    document.getElementById('hash-output').value = hashHex;
}

// ==========================================
// 3 & 4. Encoders / Decoders
// ==========================================
function base64Encode() {
    const input = document.getElementById('base64-input').value;
    try { document.getElementById('base64-output').value = btoa(input); } 
    catch(e) { document.getElementById('base64-output').value = "Error: Invalid input"; }
}
function base64Decode() {
    const input = document.getElementById('base64-input').value;
    try { document.getElementById('base64-output').value = atob(input); } 
    catch(e) { document.getElementById('base64-output').value = "Error: Invalid Base64"; }
}

function urlEncode() {
    const input = document.getElementById('url-input').value;
    document.getElementById('url-output').value = encodeURIComponent(input);
}
function urlDecode() {
    const input = document.getElementById('url-input').value;
    try { document.getElementById('url-output').value = decodeURIComponent(input); }
    catch(e) { document.getElementById('url-output').value = "Error: Malformed URL"; }
}

// ==========================================
// 5. IP Lookup (Uses Public API)
// ==========================================
function lookupIP() {
    const ip = document.getElementById('ip-input').value;
    const output = document.getElementById('ip-output');
    
    output.value = "Consultando base de datos...";
    
    // Si está vacío, busca la propia IP
    let url = ip ? `https://ipapi.co/${ip}/json/` : 'https://ipapi.co/json/';

    fetch(url)
        .then(response => response.json())
        .then(data => {
            output.value = `IP: ${data.ip}\nCiudad: ${data.city}\nRegión: ${data.region}\nPaís: ${data.country_name}\nISP: ${data.org}`;
        })
        .catch(err => {
            output.value = "Error: No se pudo conectar a la API (Puede que el AdBlock lo bloquee).";
        });
}

function getMyIP() {
    document.getElementById('ip-input').value = "";
    lookupIP();
}

// ==========================================
// 6. JWT Decoder
// ==========================================
function decodeJWT() {
    const token = document.getElementById('jwt-input').value;
    const output = document.getElementById('jwt-output');
    
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        output.value = JSON.stringify(JSON.parse(jsonPayload), null, 4);
    } catch (e) {
        output.value = "Error: Token JWT inválido.";
    }
}

// ==========================================
// 7. SQL Injection & 8. XSS Payload Generator
// ==========================================
function generateSQLi() {
    const type = document.getElementById('sqli-type').value;
    let payloads = "";
    
    if(type === 'union') payloads = "' UNION SELECT NULL, NULL--\n' UNION SELECT username, password FROM users--";
    if(type === 'error') payloads = "' OR 1=1--\n' OR 'a'='a";
    if(type === 'blind') payloads = "' AND SLEEP(5)--\n'; WAITFOR DELAY '0:0:5'--";
    
    document.getElementById('sqli-output').value = payloads;
}

function generateXSS() {
    const type = document.getElementById('xss-type').value;
    let payloads = "";
    
    if(type === 'basic') payloads = "<script>alert('XSS')</script>";
    if(type === 'img') payloads = "<img src=x onerror=alert(1)>";
    if(type === 'svg') payloads = "<svg/onload=alert(1)>";
    
    document.getElementById('xss-output').value = payloads;
}

// ==========================================
// 9. Hex/Bin Converter
// ==========================================
function convertNumber() {
    const input = document.getElementById('converter-input').value;
    const from = document.getElementById('converter-from').value;
    const output = document.getElementById('converter-output');
    
    let decimal = 0;
    try {
        if(from === 'dec') decimal = parseInt(input, 10);
        if(from === 'hex') decimal = parseInt(input, 16);
        if(from === 'bin') decimal = parseInt(input, 2);

        if(isNaN(decimal)) throw "NaN";

        output.value = `DEC: ${decimal}\nHEX: ${decimal.toString(16).toUpperCase()}\nBIN: ${decimal.toString(2)}`;
    } catch (e) {
        output.value = "Error: Entrada inválida";
    }
}

// ==========================================
// 10. Lorem Ipsum
// ==========================================
function generateLorem() {
    const count = document.getElementById('lorem-count').value;
    const text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. ";
    let result = "";
    for(let i=0; i<count; i++) result += text + "\n\n";
    document.getElementById('lorem-output').value = result;
    document.getElementById('lorem-count-val').innerText = count;
}
document.getElementById('lorem-count').addEventListener('input', function() {
    document.getElementById('lorem-count-val').innerText = this.value;
});

// ==========================================
// 14. Smart Password AI (Visualizer)
// ==========================================
function analyzePasswordAI() {
    const pwd = document.getElementById('smart-pwd-input').value;
    const bar = document.getElementById('ai-bar');
    const scoreText = document.getElementById('ai-score');
    const feedback = document.getElementById('ai-feedback');
    const timeText = document.getElementById('ai-time');

    let score = 0;
    if (pwd.length > 8) score += 20;
    if (pwd.length > 12) score += 20;
    if (/[A-Z]/.test(pwd)) score += 15;
    if (/[0-9]/.test(pwd)) score += 15;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 30;

    if (score > 100) score = 100;

    // Colores
    let color = 'red';
    let time = 'Instantáneo';
    
    if (score > 40) { color = 'orange'; time = '2 horas'; }
    if (score > 60) { color = '#ffbd2e'; time = '3 semanas'; }
    if (score > 80) { color = '#00ff41'; time = '200 años'; }

    bar.style.width = score + "%";
    bar.style.background = color;
    scoreText.innerText = score + "/100";
    scoreText.style.color = color;
    timeText.innerText = "Crackeo: " + time;

    if(score < 50) feedback.innerText = "⚠️ Muy débil. Añade símbolos y números.";
    else if(score < 80) feedback.innerText = "🛡️ Decente. Podría ser más larga.";
    else feedback.innerText = "🔒 Excelente. Calidad militar.";
}

// ==========================================
// 15. Port Scanner Simulator
// ==========================================
function simulatePortScan() {
    const ip = document.getElementById('port-ip').value || "192.168.1.1";
    const results = document.getElementById('port-results');
    results.innerHTML = `<div>[+] Iniciando escaneo en ${ip}...</div>`;
    
    const ports = [21, 22, 80, 443, 3306, 8080];
    let delay = 500;

    ports.forEach(port => {
        setTimeout(() => {
            const status = Math.random() > 0.5 ? "OPEN" : "CLOSED";
            const color = status === "OPEN" ? "#00ff41" : "#ff0055";
            results.innerHTML += `<div style="color:${color}">Port ${port}/tcp: ${status}</div>`;
        }, delay);
        delay += 600;
    });
}

// ==========================================
// Utilities
// ==========================================
function copyToClipboard(id) {
    const copyText = document.getElementById(id);
    copyText.select();
    copyText.setSelectionRange(0, 99999); 
    document.execCommand("copy"); // Fallback for older browsers
    // Modern: navigator.clipboard.writeText(copyText.value);
    alert("Copiado: " + copyText.value.substring(0, 20) + "...");
}
