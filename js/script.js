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
        }, 20);
    }

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
