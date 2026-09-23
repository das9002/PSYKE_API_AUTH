(function (global) {
    'use strict';

    /* ==========================================================================
       1. Bencho Tilt Card Component (3D Tilt + Dynamic Light Glare)
       ========================================================================== */
    function initBenchoTilt() {
        const SELECTOR = '.card-dashboard, .card-section, .card-custom, .card-transferido, .split-card, .stat-card';
        const cards = document.querySelectorAll(SELECTOR);

        cards.forEach((card) => {
            if (card.dataset.benchoTiltInited) return;
            card.dataset.benchoTiltInited = 'true';
            card.classList.add('bencho-tilt-card');

            let glare = card.querySelector('.bencho-glare');
            if (!glare) {
                glare = document.createElement('div');
                glare.className = 'bencho-glare';
                card.appendChild(glare);
            }

            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                const centerX = rect.width / 2;
                const centerY = rect.height / 2;

                const rotateX = ((y - centerY) / centerY) * -8; // Max 8deg tilt
                const rotateY = ((x - centerX) / centerX) * 8;

                card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) scale3d(1.02, 1.02, 1.02)`;

                if (glare) {
                    glare.style.opacity = '1';
                    glare.style.background = `radial-gradient(circle at ${x}px ${y}px, rgba(255,255,255,0.2) 0%, rgba(255,255,255,0) 70%)`;
                }
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
                if (glare) {
                    glare.style.opacity = '0';
                }
            });
        });
    }

    /* ==========================================================================
       2. Command Bar Palette (Ctrl + K Search & Jump)
       ========================================================================== */
    const COMMAND_ITEMS = [
        { section: 'Navegación', title: 'Inicio / Panel Principal', icon: 'bi-house-door-fill', url: 'inicio.html' },
        { section: 'Navegación', title: 'Citas y Agenda', icon: 'bi-calendar3-event-fill', url: 'citas.html' },
        { section: 'Navegación', title: 'Gestión de Estudiantes', icon: 'bi-people-fill', url: 'estudiante.html' },
        { section: 'Navegación', title: 'Directorio de Psicólogos', icon: 'bi-person-badge-fill', url: 'psicologos.html' },
        { section: 'Navegación', title: 'Casos Transferidos', icon: 'bi-arrow-left-right', url: 'casosTransferidos.html' },
        { section: 'Navegación', title: 'Seguimientos de Expediente', icon: 'bi-graph-up-arrow', url: 'seguimientos.html' },
        { section: 'Navegación', title: 'Tests Personalizados', icon: 'bi-clipboard-check-fill', url: 'tests.html' },
        { section: 'Navegación', title: 'Configuración del Sistema', icon: 'bi-gear-fill', url: 'config.html' },
        { section: 'Cuenta', title: 'Mi Perfil de Usuario', icon: 'bi-person-circle', url: 'perfilConfig.html' },
        { section: 'Cuenta', title: 'Cambiar Contraseña', icon: 'bi-shield-lock-fill', url: 'cambiocontraseña.html' },
        { section: 'Acciones Rápidas', title: 'Alternar Modo Oscuro', icon: 'bi-moon-stars-fill', action: 'toggle-dark' },
        { section: 'Acciones Rápidas', title: 'Cerrar Sesión', icon: 'bi-box-arrow-right', action: 'logout' }
    ];

    let cmdOverlay = null;
    let cmdInput = null;
    let cmdResults = null;
    let activeIndex = 0;

    function getRelativeUrl(path) {
        const isBtnsFolder = /\/btnsEstudiante(\/|$)/.test(window.location.pathname);
        return isBtnsFolder ? '../HTML/' + path : path;
    }

    function buildCmdBar() {
        if (cmdOverlay) return;

        cmdOverlay = document.createElement('div');
        cmdOverlay.className = 'bencho-cmd-overlay';
        cmdOverlay.id = 'benchoCmdOverlay';

        cmdOverlay.innerHTML = `
            <div class="bencho-cmd-modal" role="dialog" aria-modal="true">
                <div class="bencho-cmd-header">
                    <i class="bi bi-search"></i>
                    <input type="text" class="bencho-cmd-input" placeholder="Escribe un comando o busca en Psyke..." aria-label="Buscar comandos">
                    <span class="bencho-cmd-shortcut-badge">ESC</span>
                </div>
                <div class="bencho-cmd-results" id="benchoCmdResults"></div>
                <div class="bencho-cmd-footer">
                    <div class="bencho-cmd-key-hints">
                        <span><kbd>↑</kbd> <kbd>↓</kbd> Navegar</span>
                        <span><kbd>↵</kbd> Seleccionar</span>
                        <span><kbd>ESC</kbd> Cerrar</span>
                    </div>
                    <div>Psyke Interactive Command Bar</div>
                </div>
            </div>
        `;

        document.body.appendChild(cmdOverlay);

        cmdInput = cmdOverlay.querySelector('.bencho-cmd-input');
        cmdResults = cmdOverlay.querySelector('.bencho-cmd-results');

        cmdOverlay.addEventListener('click', (e) => {
            if (e.target === cmdOverlay) hideCmdBar();
        });

        cmdInput.addEventListener('input', renderCmdResults);

        cmdInput.addEventListener('keydown', (e) => {
            const items = cmdResults.querySelectorAll('.bencho-cmd-item');
            if (items.length === 0) return;

            if (e.key === 'ArrowDown') {
                e.preventDefault();
                activeIndex = (activeIndex + 1) % items.length;
                updateActiveCmdItem(items);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                activeIndex = (activeIndex - 1 + items.length) % items.length;
                updateActiveCmdItem(items);
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (items[activeIndex]) {
                    items[activeIndex].click();
                }
            } else if (e.key === 'Escape') {
                hideCmdBar();
            }
        });
    }

    function updateActiveCmdItem(items) {
        items.forEach((item, idx) => {
            if (idx === activeIndex) {
                item.classList.add('active');
                item.scrollIntoView({ block: 'nearest' });
            } else {
                item.classList.remove('active');
            }
        });
    }

    function renderCmdResults() {
        if (!cmdResults) return;

        const query = (cmdInput.value || '').toLowerCase().trim();
        cmdResults.innerHTML = '';

        const filtered = COMMAND_ITEMS.filter((item) =>
            item.title.toLowerCase().includes(query) || item.section.toLowerCase().includes(query)
        );

        if (filtered.length === 0) {
            cmdResults.innerHTML = `
                <div class="text-center py-4 text-muted small">
                    <i class="bi bi-search fs-3 opacity-50 d-block mb-1"></i>
                    Sin resultados para "${query}"
                </div>`;
            return;
        }

        let currentSection = '';
        let itemIndex = 0;

        filtered.forEach((item) => {
            if (item.section !== currentSection) {
                currentSection = item.section;
                const sectionEl = document.createElement('div');
                sectionEl.className = 'bencho-cmd-group-title';
                sectionEl.textContent = currentSection;
                cmdResults.appendChild(sectionEl);
            }

            const itemEl = document.createElement('a');
            itemEl.className = 'bencho-cmd-item';
            itemEl.href = item.url ? getRelativeUrl(item.url) : '#';

            itemEl.innerHTML = `
                <div class="bencho-cmd-item-content">
                    <i class="bi ${item.icon}"></i>
                    <span>${item.title}</span>
                </div>
                <i class="bi bi-arrow-return-left text-muted small opacity-50"></i>
            `;

            const currentIndex = itemIndex;
            itemEl.addEventListener('click', (e) => {
                if (item.action === 'toggle-dark') {
                    e.preventDefault();
                    toggleDarkModeGlobal();
                    hideCmdBar();
                } else if (item.action === 'logout') {
                    e.preventDefault();
                    hideCmdBar();
                    if (typeof cerrarSesionGlobal === 'function') {
                        cerrarSesionGlobal();
                    } else {
                        window.location.replace('../index.html');
                    }
                } else {
                    hideCmdBar();
                }
            });

            itemEl.addEventListener('mouseenter', () => {
                activeIndex = currentIndex;
                const items = cmdResults.querySelectorAll('.bencho-cmd-item');
                updateActiveCmdItem(items);
            });

            cmdResults.appendChild(itemEl);
            itemIndex++;
        });

        activeIndex = 0;
        const items = cmdResults.querySelectorAll('.bencho-cmd-item');
        updateActiveCmdItem(items);
    }

    function showCmdBar() {
        buildCmdBar();
        cmdOverlay.classList.add('active');
        cmdInput.value = '';
        renderCmdResults();
        setTimeout(() => cmdInput.focus(), 50);
    }

    function hideCmdBar() {
        if (cmdOverlay) {
            cmdOverlay.classList.remove('active');
        }
    }

    function toggleDarkModeGlobal() {
        const isDark = document.documentElement.classList.toggle('dark-mode');
        localStorage.setItem('psyke_dark_mode', isDark ? 'enabled' : 'disabled');
        const sw = document.getElementById('switchOscuro');
        if (sw) sw.checked = isDark;
        if (typeof Notif !== 'undefined') {
            Notif.exito(isDark ? 'Modo oscuro activado' : 'Modo claro activado', 'Apariencia');
        }
    }

    function initCmdKeybinds() {
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                showCmdBar();
            } else if (e.key === 'Escape' && cmdOverlay && cmdOverlay.classList.contains('active')) {
                hideCmdBar();
            }
        });

        // Attach to topbar search inputs / search icons
        document.addEventListener('click', (e) => {
            const target = e.target.closest('#searchRecentStudents, .search-box-container, .bi-search');
            if (target && !e.target.closest('#benchoCmdOverlay')) {
                // If on mobile or clicked directly on search icon
                if (e.target.classList.contains('bi-search')) {
                    e.preventDefault();
                    showCmdBar();
                }
            }
        });
    }

    /* ==========================================================================
       3. Slide to Confirm Component (Interactive Drag Confirm)
       ========================================================================== */
    function createSlideToConfirm(containerEl, options = {}) {
        if (!containerEl) return;

        const text = options.text || 'Desliza para confirmar';
        const completedText = options.completedText || 'Confirmado ✓';
        const onConfirm = options.onConfirm || function () {};

        containerEl.innerHTML = `
            <div class="bencho-slide-confirm" id="benchoSlideConfirm">
                <div class="bencho-slide-fill"></div>
                <div class="bencho-slide-label">${text}</div>
                <div class="bencho-slide-handle">
                    <i class="bi bi-chevron-double-right"></i>
                </div>
            </div>
        `;

        const slideBox = containerEl.querySelector('.bencho-slide-confirm');
        const fill = slideBox.querySelector('.bencho-slide-fill');
        const label = slideBox.querySelector('.bencho-slide-label');
        const handle = slideBox.querySelector('.bencho-slide-handle');

        let isDragging = false;
        let startX = 0;
        let currentX = 0;
        let maxDrag = 0;

        function updateMaxDrag() {
            maxDrag = slideBox.clientWidth - handle.clientWidth - 8;
        }

        updateMaxDrag();
        window.addEventListener('resize', updateMaxDrag);

        function startDrag(clientX) {
            if (slideBox.classList.contains('completed')) return;
            isDragging = true;
            startX = clientX - currentX;
            slideBox.classList.add('dragging');
        }

        function moveDrag(clientX) {
            if (!isDragging) return;
            currentX = clientX - startX;
            if (currentX < 0) currentX = 0;
            if (currentX > maxDrag) currentX = maxDrag;

            handle.style.transform = `translateX(${currentX}px)`;
            const percent = (currentX / maxDrag) * 100;
            fill.style.width = `${percent}%`;

            if (percent > 85) {
                completeSlide();
            }
        }

        function endDrag() {
            if (!isDragging) return;
            isDragging = false;
            slideBox.classList.remove('dragging');

            if (!slideBox.classList.contains('completed')) {
                // Reset slide
                currentX = 0;
                handle.style.transform = 'translateX(0px)';
                fill.style.width = '0%';
            }
        }

        function completeSlide() {
            isDragging = false;
            slideBox.classList.add('completed');
            currentX = maxDrag;
            handle.style.transform = `translateX(${maxDrag}px)`;
            fill.style.width = '100%';
            label.textContent = completedText;
            handle.innerHTML = '<i class="bi bi-check-lg"></i>';

            setTimeout(() => {
                onConfirm();
            }, 300);
        }

        handle.addEventListener('mousedown', (e) => startDrag(e.clientX));
        window.addEventListener('mousemove', (e) => moveDrag(e.clientX));
        window.addEventListener('mouseup', endDrag);

        handle.addEventListener('touchstart', (e) => startDrag(e.touches[0].clientX), { passive: true });
        window.addEventListener('touchmove', (e) => moveDrag(e.touches[0].clientX), { passive: true });
        window.addEventListener('touchend', endDrag);
    }

    /* ==========================================================================
       4. Liquid Toggle Switch Component
       ========================================================================== */
    function initBenchoLiquidToggle() {
        const switches = document.querySelectorAll('#switchOscuro, .form-switch input[type="checkbox"]');

        switches.forEach((sw) => {
            if (sw.dataset.benchoLiquidInited) return;
            sw.dataset.benchoLiquidInited = 'true';

            const parent = sw.parentElement;
            if (!parent) return;

            // Replace standard switch styling wrapper with liquid toggle style
            const liquidWrapper = document.createElement('div');
            liquidWrapper.className = `bencho-liquid-toggle ${sw.checked ? 'active' : ''}`;
            liquidWrapper.innerHTML = `
                <div class="bencho-liquid-thumb">
                    <i class="bi ${sw.checked ? 'bi-moon-stars-fill' : 'bi-sun-fill'}"></i>
                </div>
            `;

            sw.style.display = 'none';
            parent.appendChild(liquidWrapper);

            liquidWrapper.addEventListener('click', () => {
                sw.checked = !sw.checked;
                sw.dispatchEvent(new Event('change', { bubbles: true }));

                liquidWrapper.classList.toggle('active', sw.checked);
                const icon = liquidWrapper.querySelector('.bencho-liquid-thumb i');
                if (icon) {
                    icon.className = `bi ${sw.checked ? 'bi-moon-stars-fill' : 'bi-sun-fill'}`;
                }
            });

            sw.addEventListener('change', () => {
                liquidWrapper.classList.toggle('active', sw.checked);
                const icon = liquidWrapper.querySelector('.bencho-liquid-thumb i');
                if (icon) {
                    icon.className = `bi ${sw.checked ? 'bi-moon-stars-fill' : 'bi-sun-fill'}`;
                }
            });
        });
    }

    /* ==========================================================================
       Initialization
       ========================================================================== */
    function initAll() {
        initBenchoTilt();
        initCmdKeybinds();
        initBenchoLiquidToggle();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initAll);
    } else {
        initAll();
    }

    // Export globally
    global.BenchoUI = {
        initTilt: initBenchoTilt,
        showCmdBar: showCmdBar,
        hideCmdBar: hideCmdBar,
        createSlideToConfirm: createSlideToConfirm,
        initLiquidToggle: initBenchoLiquidToggle
    };

})(window);