// ============================================
// CYBERNEXUS ADMIN PANEL
// ============================================

// Check if user is logged in on page load
document.addEventListener('DOMContentLoaded', function () {
    const isLoggedIn = localStorage.getItem('admin_logged_in');
    if (isLoggedIn === 'true') {
        showAdminPanel();
        loadDashboardData();
    }
});

// ============================================
// AUTHENTICATION
// ============================================
function login() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    // Simple authentication (in production, use proper backend)
    if (username === 'admin' && password === 'admin123') {
        localStorage.setItem('admin_logged_in', 'true');
        localStorage.setItem('admin_username', username);
        showAdminPanel();
        loadDashboardData();
    } else {
        alert('Usuario o contraseña incorrectos');
    }
}

function logout() {
    if (confirm('¿Seguro que quieres cerrar sesión?')) {
        localStorage.removeItem('admin_logged_in');
        localStorage.removeItem('admin_username');
        location.reload();
    }
}

function showAdminPanel() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('admin-panel').style.display = 'flex';
}

// ============================================
// NAVIGATION
// ============================================
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.admin-section').forEach(section => {
        section.classList.remove('active');
    });

    // Remove active class from all nav items
    document.querySelectorAll('.admin-nav-item').forEach(item => {
        item.classList.remove('active');
    });

    // Show selected section
    document.getElementById(sectionId).classList.add('active');

    // Add active class to clicked nav item
    event.target.closest('.admin-nav-item').classList.add('active');

    // Load section-specific data
    if (sectionId === 'dashboard') {
        loadDashboardData();
    } else if (sectionId === 'analytics') {
        loadAnalyticsData();
    }
}

// ============================================
// DASHBOARD
// ============================================
function loadDashboardData() {
    // Get or initialize visit count
    let visits = parseInt(localStorage.getItem('site_visits') || '0');
    document.getElementById('total-visits').textContent = visits.toLocaleString();

    // Get or initialize subscribers
    let subscribers = parseInt(localStorage.getItem('email_subscribers') || '0');
    document.getElementById('total-subscribers').textContent = subscribers.toLocaleString();

    // Generate chart
    generateVisitsChart();
}

function generateVisitsChart() {
    const chartContainer = document.getElementById('visits-chart');
    chartContainer.innerHTML = '';

    // Generate random data for last 7 days
    const days = ['Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb', 'Dom'];
    const data = Array.from({ length: 7 }, () => Math.floor(Math.random() * 200) + 50);
    const maxValue = Math.max(...data);

    days.forEach((day, index) => {
        const bar = document.createElement('div');
        bar.className = 'chart-bar';
        bar.style.height = `${(data[index] / maxValue) * 100}%`;
        bar.title = `${day}: ${data[index]} visitas`;

        const label = document.createElement('div');
        label.className = 'chart-label';
        label.textContent = day;
        bar.appendChild(label);

        chartContainer.appendChild(bar);
    });
}

// ============================================
// CONTENT MANAGEMENT
// ============================================
function showAddArticle() {
    document.getElementById('article-form').style.display = 'block';
}

function hideAddArticle() {
    document.getElementById('article-form').style.display = 'none';
    clearArticleForm();
}

function clearArticleForm() {
    document.getElementById('article-title').value = '';
    document.getElementById('article-meta').value = '';
    document.getElementById('article-content').value = '';
    document.getElementById('article-category').selectedIndex = 0;
}

function saveArticle() {
    const title = document.getElementById('article-title').value;
    const meta = document.getElementById('article-meta').value;
    const content = document.getElementById('article-content').value;
    const category = document.getElementById('article-category').value;

    if (!title || !content) {
        alert('El título y contenido son obligatorios');
        return;
    }

    // Get existing articles from localStorage
    let articles = JSON.parse(localStorage.getItem('articles') || '[]');

    // Create new article object
    const newArticle = {
        id: Date.now(),
        title: title,
        meta: meta,
        content: content,
        category: category,
        date: new Date().toISOString().split('T')[0],
        views: 0
    };

    // Add to articles array
    articles.push(newArticle);

    // Save to localStorage
    localStorage.setItem('articles', JSON.stringify(articles));

    alert('Artículo guardado exitosamente!');
    hideAddArticle();
    loadArticlesList();
}

function loadArticlesList() {
    const articles = JSON.parse(localStorage.getItem('articles') || '[]');
    const tbody = document.getElementById('articles-list');

    if (articles.length === 0) return;

    tbody.innerHTML = '';

    articles.forEach(article => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${article.title}</td>
            <td>${article.category}</td>
            <td>${article.date}</td>
            <td>
                <button class="btn-admin" style="padding: 6px 12px;" onclick="editArticle(${article.id})">Editar</button>
                <button class="btn-admin btn-danger" style="padding: 6px 12px;" onclick="deleteArticle(${article.id})">Eliminar</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function editArticle(id) {
    const articles = JSON.parse(localStorage.getItem('articles') || '[]');
    const article = articles.find(a => a.id === id);

    if (article) {
        document.getElementById('article-title').value = article.title;
        document.getElementById('article-meta').value = article.meta;
        document.getElementById('article-content').value = article.content;
        document.getElementById('article-category').value = article.category;
        showAddArticle();

        // Delete old article when saving
        deleteArticle(id, false);
    }
}

function deleteArticle(id, confirm = true) {
    if (confirm && !window.confirm('¿Seguro que quieres eliminar este artículo?')) {
        return;
    }

    let articles = JSON.parse(localStorage.getItem('articles') || '[]');
    articles = articles.filter(a => a.id !== id);
    localStorage.setItem('articles', JSON.stringify(articles));

    if (confirm) {
        alert('Artículo eliminado');
        loadArticlesList();
    }
}

// ============================================
// ANALYTICS
// ============================================
function loadAnalyticsData() {
    // This would connect to Google Analytics API in production
    console.log('Loading analytics data...');
}

// ============================================
// SETTINGS
// ============================================
function saveAffiliateLinks() {
    const vpn = document.getElementById('affiliate-vpn').value;
    const hosting = document.getElementById('affiliate-hosting').value;
    const courses = document.getElementById('affiliate-courses').value;

    localStorage.setItem('affiliate_vpn', vpn);
    localStorage.setItem('affiliate_hosting', hosting);
    localStorage.setItem('affiliate_courses', courses);

    alert('Enlaces de afiliados guardados!');
}

function saveSEOSettings() {
    const gaId = document.getElementById('ga-id').value;
    const metaDesc = document.getElementById('meta-desc').value;

    localStorage.setItem('ga_id', gaId);
    localStorage.setItem('meta_description', metaDesc);

    alert('Configuración SEO guardada!');
}

// Load saved settings on page load
function loadSettings() {
    const vpn = localStorage.getItem('affiliate_vpn') || '';
    const hosting = localStorage.getItem('affiliate_hosting') || '';
    const courses = localStorage.getItem('affiliate_courses') || '';
    const gaId = localStorage.getItem('ga_id') || '';
    const metaDesc = localStorage.getItem('meta_description') || '';

    if (document.getElementById('affiliate-vpn')) {
        document.getElementById('affiliate-vpn').value = vpn;
        document.getElementById('affiliate-hosting').value = hosting;
        document.getElementById('affiliate-courses').value = courses;
        document.getElementById('ga-id').value = gaId;
        document.getElementById('meta-desc').value = metaDesc;
    }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================
function incrementVisitCount() {
    let visits = parseInt(localStorage.getItem('site_visits') || '0');
    visits++;
    localStorage.setItem('site_visits', visits.toString());
}

function addEmailSubscriber(email) {
    let subscribers = JSON.parse(localStorage.getItem('subscribers_list') || '[]');
    if (!subscribers.includes(email)) {
        subscribers.push(email);
        localStorage.setItem('subscribers_list', JSON.stringify(subscribers));

        let count = parseInt(localStorage.getItem('email_subscribers') || '0');
        count++;
        localStorage.setItem('email_subscribers', count.toString());
    }
}

    }
}

// ============================================
// BACKUP & RESTORE
// ============================================
function exportData() {
    const data = {
        articles: localStorage.getItem('articles'),
        site_visits: localStorage.getItem('site_visits'),
        email_subscribers: localStorage.getItem('email_subscribers'),
        subscribers_list: localStorage.getItem('subscribers_list'),
        affiliate_vpn: localStorage.getItem('affiliate_vpn'),
        affiliate_hosting: localStorage.getItem('affiliate_hosting'),
        affiliate_courses: localStorage.getItem('affiliate_courses'),
        ga_id: localStorage.getItem('ga_id'),
        meta_description: localStorage.getItem('meta_description'),
        theme: localStorage.getItem('theme'),
        export_date: new Date().toISOString()
    };

    const dataStr = JSON.stringify(data, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `cybernexus_backup_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    alert('Copia de seguridad descargada correctamente.');
}

function triggerImport() {
    document.getElementById('import-file').click();
}

function importData(input) {
    const file = input.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        try {
            const data = JSON.parse(e.target.result);

            if (confirm('¿Estás seguro? Esto sobrescribirá los datos actuales con los de la copia de seguridad.')) {
                if (data.articles) localStorage.setItem('articles', data.articles);
                if (data.site_visits) localStorage.setItem('site_visits', data.site_visits);
                if (data.email_subscribers) localStorage.setItem('email_subscribers', data.email_subscribers);
                if (data.subscribers_list) localStorage.setItem('subscribers_list', data.subscribers_list);
                if (data.affiliate_vpn) localStorage.setItem('affiliate_vpn', data.affiliate_vpn);
                if (data.affiliate_hosting) localStorage.setItem('affiliate_hosting', data.affiliate_hosting);
                if (data.affiliate_courses) localStorage.setItem('affiliate_courses', data.affiliate_courses);
                if (data.ga_id) localStorage.setItem('ga_id', data.ga_id);
                if (data.meta_description) localStorage.setItem('meta_description', data.meta_description);
                if (data.theme) localStorage.setItem('theme', data.theme);

                alert('Datos restaurados exitosamente. La página se recargará.');
                location.reload();
            }
        } catch (err) {
            alert('Error al importar el archivo: Formato inválido.');
            console.error(err);
        }
    };
    reader.readAsText(file);
    input.value = ''; // Reset input
}

// ============================================
// SMART EDITOR & TEMPLATES
// ============================================
function updatePreview() {
    const content = document.getElementById('article-content').value;
    const preview = document.getElementById('article-preview');

    if (!content) {
        preview.innerHTML = '<p style="color: #666; text-align: center; margin-top: 200px;">Vista Previa en Vivo</p>';
        return;
    }

    // Basic markdown-like to HTML conversion for preview (optional, or just render HTML)
    // For now, we assume user writes HTML or plain text
    preview.innerHTML = content;
}

function insertTemplate(type) {
    const textarea = document.getElementById('article-content');
    let template = '';

    if (type === 'tutorial') {
        template = `<h3>Introducción</h3>
<p>En este tutorial aprenderemos a...</p>

<h3>Requisitos Previos</h3>
<ul>
    <li>Kali Linux instalado</li>
    <li>Conocimientos básicos de terminal</li>
</ul>

<h3>Paso 1: Instalación</h3>
<p>Ejecuta el siguiente comando:</p>
<pre><code>sudo apt update && sudo apt install tool</code></pre>

<h3>Conclusión</h3>
<p>Ahora ya sabes cómo utilizar esta herramienta...</p>`;
    } else if (type === 'news') {
        template = `<h3>Resumen de la Noticia</h3>
<p>Hoy se ha descubierto una nueva vulnerabilidad crítica en...</p>

<h3>Detalles Técnicos</h3>
<p>El fallo, identificado como CVE-2025-XXXX, permite a los atacantes...</p>

<h3>Impacto y Solución</h3>
<p>Se recomienda actualizar inmediatamente a la versión...</p>`;
    } else if (type === 'review') {
        template = `<h3>Análisis de Herramienta</h3>
<p>Hemos probado a fondo la nueva versión de...</p>

<h3>Pros</h3>
<ul>
    <li>Interfaz intuitiva</li>
    <li>Rápida ejecución</li>
</ul>

<h3>Contras</h3>
<ul>
    <li>Documentación escasa</li>
</ul>

<h3>Veredicto Final</h3>
<p>Recomendamos esta herramienta para...</p>`;
    }

    textarea.value = template;
    updatePreview();
}

// Initialize on load
setTimeout(() => {
    loadSettings();
    loadArticlesList();
}, 500);
