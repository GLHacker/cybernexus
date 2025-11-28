document.addEventListener('DOMContentLoaded', () => {
    // Typing Effect
    const textElement = document.getElementById('typing-text');
    if (textElement) {
        const texts = [
            "Iniciando sistema...",
            "Cargando módulos de ciberseguridad...",
            "Accediendo a la red neuronal...",
            "Bienvenido a CyberNexus."
        ];

        let textIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        let typeSpeed = 80;

        function type() {
            const currentText = texts[textIndex];

            if (isDeleting) {
                textElement.textContent = currentText.substring(0, charIndex - 1);
                charIndex--;
                typeSpeed = 40;
            } else {
                textElement.textContent = currentText.substring(0, charIndex + 1);
                charIndex++;
                typeSpeed = 80;
            }

            if (!isDeleting && charIndex === currentText.length) {
                isDeleting = true;
                typeSpeed = 2000; // Pause at end
            } else if (isDeleting && charIndex === 0) {
                isDeleting = false;
                textIndex = (textIndex + 1) % texts.length;
                typeSpeed = 500; // Pause before new text
            }

            setTimeout(type, typeSpeed);
        }

        type();
    }

    // Visitor Counter (Simulated with LocalStorage)
    const counterElement = document.getElementById('counter');
    if (counterElement) {
        let visits = localStorage.getItem('page_visits');

        if (!visits) {
            visits = 1240; // Fake starting number
        } else {
            visits = parseInt(visits) + 1;
        }

        localStorage.setItem('page_visits', visits);

        // Animate counter
        let current = 0;
        const increment = Math.ceil(visits / 50);

        const timer = setInterval(() => {
            current += increment;
            if (current >= visits) {
                current = visits;
                clearInterval(timer);
            }
            counterElement.textContent = current.toLocaleString();
        }, 100);
    }

    // ============================================
    // SEARCH FUNCTIONALITY
    // ============================================
    function initSearch() {
        const searchBtn = document.createElement('button');
        searchBtn.innerHTML = '<i class="fas fa-search"></i>';
        searchBtn.className = 'search-toggle';
        searchBtn.style.cssText = 'position: fixed; bottom: 20px; right: 20px; width: 50px; height: 50px; border-radius: 50%; background: var(--primary-color); border: none; color: #000; cursor: pointer; z-index: 1000; box-shadow: 0 4px 12px rgba(0,255,65,0.3);';
        searchBtn.onclick = toggleSearch;
        document.body.appendChild(searchBtn);
    }

    function toggleSearch() {
        let searchModal = document.getElementById('search-modal');
        if (!searchModal) {
            searchModal = createSearchModal();
            document.body.appendChild(searchModal);
        }
        searchModal.style.display = searchModal.style.display === 'flex' ? 'none' : 'flex';
        if (searchModal.style.display === 'flex') {
            document.getElementById('search-input').focus();
        }
    }

    function createSearchModal() {
        const modal = document.createElement('div');
        modal.id = 'search-modal';
        modal.style.cssText = 'display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.95); z-index: 10000; justify-content: center; align-items: flex-start; padding-top: 100px;';
        modal.innerHTML = `
            <div style="max-width: 600px; width: 90%; background: var(--bg-panel); padding: 30px; border: 1px solid #222; border-radius: 8px;">
                <input type="text" id="search-input" placeholder="Buscar en el sitio..." style="width: 100%; padding: 15px; background: #000; border: 1px solid var(--primary-color); color: #fff; font-family: var(--font-main); font-size: 1.1rem; border-radius: 4px; margin-bottom: 20px;" oninput="performSearch()">
                <div id="search-results" style="max-height: 400px; overflow-y: auto;"></div>
                <button onclick="toggleSearch()" style="margin-top: 20px; padding: 10px 20px; background: rgba(255,0,85,0.1); border: 1px solid #ff0055; color: #ff0055; cursor: pointer; border-radius: 4px; font-family: var(--font-main);">Cerrar</button>
            </div>
        `;
        return modal;
    }

    function performSearch() {
        const query = document.getElementById('search-input').value.toLowerCase();
        const resultsDiv = document.getElementById('search-results');

        if (query.length < 2) {
            resultsDiv.innerHTML = '<p style="color: #888;">Escribe al menos 2 caracteres...</p>';
            return;
        }

        // Search in articles (simplified - in production, use a proper search index)
        const articles = [
            { title: 'Cómo empezar en ciberseguridad desde cero', url: 'articulos/1.html', desc: 'Guía completa para principiantes' },
            { title: 'Top 10 herramientas de hacking ético', url: 'articulos/2.html', desc: 'Las mejores herramientas gratuitas' },
            { title: 'Cómo proteger tu privacidad con VPN', url: 'articulos/3.html', desc: 'Guía completa de VPNs' },
            { title: 'Mejores herramientas de IA para programadores', url: 'articulos/4.html', desc: 'IA para desarrollo' },
            { title: 'Cómo crear una web gratis y monetizarla', url: 'articulos/5.html', desc: 'Monetización web' },
            { title: 'Certificaciones de Ciberseguridad 2025', url: 'articulos/6.html', desc: 'CompTIA, OSCP, CEH' },
            { title: 'Laboratorio de pentesting con VirtualBox', url: 'articulos/7.html', desc: 'Configurar lab de hacking' },
            { title: 'Bug Bounty: Gana dinero', url: 'articulos/8.html', desc: 'Introducción a bug bounty' },
            { title: 'Python para Hackers', url: 'articulos/9.html', desc: 'Scripts esenciales' },
            { title: 'OSINT: Técnicas de investigación', url: 'articulos/10.html', desc: 'Open Source Intelligence' }
        ];

        const results = articles.filter(article =>
            article.title.toLowerCase().includes(query) ||
            article.desc.toLowerCase().includes(query)
        );

        if (results.length === 0) {
            resultsDiv.innerHTML = '<p style="color: #888;">No se encontraron resultados.</p>';
            return;
        }

        resultsDiv.innerHTML = results.map(article => `
            <div style="padding: 15px; margin-bottom: 10px; background: rgba(0,255,65,0.05); border: 1px solid #222; border-radius: 4px;">
                <h4 style="color: var(--primary-color); margin-bottom: 5px;"><a href="${article.url}" style="color: var(--primary-color); text-decoration: none;">${article.title}</a></h4>
                <p style="color: #888; font-size: 0.9rem;">${article.desc}</p>
            </div>
        `).join('');
    }

    // ============================================
    // THEME TOGGLE
    // ============================================
    function initThemeToggle() {
        const themeBtn = document.createElement('button');
        themeBtn.innerHTML = '<i class="fas fa-moon"></i>';
        themeBtn.className = 'theme-toggle';
        themeBtn.style.cssText = 'position: fixed; bottom: 20px; right: 90px; width: 50px; height: 50px; border-radius: 50%; background: rgba(0,255,65,0.1); border: 1px solid var(--primary-color); color: var(--primary-color); cursor: pointer; z-index: 1000;';
        themeBtn.onclick = toggleTheme;
        document.body.appendChild(themeBtn);

        // Load saved theme
        const savedTheme = localStorage.getItem('theme') || 'dark';
        if (savedTheme === 'light') {
            applyLightTheme();
        }
    }

    function toggleTheme() {
        const currentTheme = localStorage.getItem('theme') || 'dark';
        if (currentTheme === 'dark') {
            applyLightTheme();
            localStorage.setItem('theme', 'light');
        } else {
            applyDarkTheme();
            localStorage.setItem('theme', 'dark');
        }
    }

    function applyLightTheme() {
        document.documentElement.style.setProperty('--bg-main', '#f5f5f5');
        document.documentElement.style.setProperty('--bg-panel', '#ffffff');
        document.documentElement.style.setProperty('--text-primary', '#000000');
        const themeToggleBtn = document.querySelector('.theme-toggle');
        if (themeToggleBtn) {
            themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>';
        }
        document.body.style.color = '#000';
    }

    function applyDarkTheme() {
        document.documentElement.style.setProperty('--bg-main', '#0a0a0a');
        document.documentElement.style.setProperty('--bg-panel', '#111');
        document.documentElement.style.setProperty('--text-primary', '#00ff41');
        const themeToggleBtn = document.querySelector('.theme-toggle');
        if (themeToggleBtn) {
            themeToggleBtn.innerHTML = '<i class="fas fa-moon"></i>';
        }
        document.body.style.color = '#fff';
    }

    // Initialize new features
    initSearch();
    initThemeToggle();

    // Mobile Menu Toggle
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav-links');

    if (hamburger) {
        hamburger.addEventListener('click', () => {
            if (navLinks.style.display === 'flex') {
                navLinks.style.display = 'none';
            } else {
                navLinks.style.display = 'flex';
                navLinks.style.flexDirection = 'column';
                navLinks.style.position = 'absolute';
                navLinks.style.top = '70px';
                navLinks.style.left = '0';
                navLinks.style.width = '100%';
                navLinks.style.background = 'rgba(5, 5, 5, 0.95)';
                navLinks.style.padding = '20px';
                navLinks.style.borderBottom = '1px solid #008f11';
                navLinks.style.zIndex = '1000';
            }
        });
    }
});
