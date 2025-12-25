// Main interactive behavior for Secure File Share
(function () {
    'use strict';

    // Theme configuration
    const THEME_KEY = 'securefileshare-theme';
    const THEMES = {
        light: {
            icon: '🌙',
            label: 'Dark Mode',
            next: 'dark'
        },
        dark: {
            icon: '☀️',
            label: 'Light Mode',
            next: 'light'
        }
    };

    // Initialize theme from localStorage or system preference
    function initTheme() {
        const savedTheme = localStorage.getItem(THEME_KEY);
        const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const defaultTheme = systemPrefersDark ? 'dark' : 'light';
        const theme = savedTheme || defaultTheme;

        applyTheme(theme);
        updateThemeToggle(theme);
    }

    // Apply theme to document
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        document.body.classList.toggle('dark-mode', theme === 'dark');

        // Store theme preference
        localStorage.setItem(THEME_KEY, theme);

        // Dispatch custom event for theme change
        document.dispatchEvent(new CustomEvent('themechange', { detail: { theme } }));
    }

    // Update theme toggle button
    function updateThemeToggle(theme) {
        const themeToggle = document.querySelector('#themeToggle');
        if (themeToggle) {
            const themeConfig = THEMES[theme];
            themeToggle.innerHTML = themeConfig.icon;
            themeToggle.setAttribute('aria-label', themeConfig.label);
            themeToggle.setAttribute('title', `Switch to ${themeConfig.next} theme`);
            themeToggle.setAttribute('aria-pressed', theme === 'dark');
        }
    }

    // Toggle theme between light and dark
    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
        applyTheme(nextTheme);
        updateThemeToggle(nextTheme);
    }

    // Mobile navigation toggle
    function initMobileNav() {
        const navToggle = document.querySelector('.nav-toggle');
        const navList = document.querySelector('.nav-list');

        if (!navToggle || !navList) return;

        // Close mobile nav when clicking outside
        document.addEventListener('click', (e) => {
            if (navList.classList.contains('open') &&
                !navToggle.contains(e.target) &&
                !navList.contains(e.target)) {
                navList.classList.remove('open');
                navToggle.setAttribute('aria-expanded', 'false');
            }
        });

        // Toggle navigation on button click
        navToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = navList.classList.toggle('open');
            navToggle.setAttribute('aria-expanded', isOpen);
        });

        // Close mobile nav when clicking a link
        navList.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navList.classList.remove('open');
                navToggle.setAttribute('aria-expanded', 'false');
            });
        });

        // Handle keyboard navigation
        navToggle.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                navToggle.click();
            }
        });
    }

    // Smooth scroll for internal links
    function initSmoothScroll() {
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            // Skip if it's a download link with hash
            if (anchor.getAttribute('href').startsWith('#/download')) return;

            anchor.addEventListener('click', function (e) {
                const href = this.getAttribute('href');

                // Only process internal anchor links
                if (href === '#' || href === '#!') return;

                const targetId = href.substring(1);
                if (!targetId) return;

                const targetElement = document.getElementById(targetId);
                if (!targetElement) return;

                e.preventDefault();

                // Close mobile nav if open
                const navList = document.querySelector('.nav-list');
                if (navList && navList.classList.contains('open')) {
                    navList.classList.remove('open');
                    document.querySelector('.nav-toggle')?.setAttribute('aria-expanded', 'false');
                }

                // Smooth scroll to target
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });

                // Update URL hash without scrolling
                history.pushState(null, null, href);
            });
        });
    }

    // Quick download functionality
    function initQuickDownload() {
        function validateFileId(fileId) {
            // Remove any non-hex characters and validate length
            const cleanId = fileId.trim().toLowerCase().replace(/[^a-f0-9]/g, '');
            return cleanId.length >= 8 && /^[a-f0-9]+$/.test(cleanId);
        }

        function handleQuickDownload(fileId) {
            if (!validateFileId(fileId)) {
                showError('Please enter a valid File ID (minimum 8 hexadecimal characters)');
                return false;
            }

            const cleanId = fileId.trim().toLowerCase().replace(/[^a-f0-9]/g, '');
            window.location.href = `/download/${cleanId}`;
            return true;
        }

        function showError(message) {
            // Remove any existing error
            const existingError = document.querySelector('.quick-error');
            if (existingError) existingError.remove();

            // Create error message
            const errorDiv = document.createElement('div');
            errorDiv.className = 'quick-error error-message';
            errorDiv.textContent = message;
            errorDiv.style.margin = '10px 0';
            errorDiv.style.padding = '10px';
            errorDiv.style.borderRadius = '4px';

            // Find where to insert the error
            const quickDemo = document.querySelector('.demo-card');
            if (quickDemo) {
                quickDemo.appendChild(errorDiv);

                // Auto-remove error after 5 seconds
                setTimeout(() => {
                    if (errorDiv.parentNode) {
                        errorDiv.style.opacity = '0';
                        errorDiv.style.transition = 'opacity 0.3s';
                        setTimeout(() => errorDiv.remove(), 300);
                    }
                }, 5000);
            }
        }

        // Handle quick download form if present
        const quickForm = document.querySelector('#quick-download-form');
        if (quickForm) {
            quickForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const input = quickForm.querySelector('input[name="file_id"]');
                if (input && input.value) {
                    handleQuickDownload(input.value);
                }
            });
        }

        // Handle quick demo input/button
        const quickInput = document.querySelector('#quickFileId');
        const quickBtn = document.querySelector('#quickDownload');

        if (quickBtn && quickInput) {
            // Button click
            quickBtn.addEventListener('click', () => {
                handleQuickDownload(quickInput.value);
            });

            // Enter key in input
            quickInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    handleQuickDownload(quickInput.value);
                }
            });

            // Clear error on input
            quickInput.addEventListener('input', () => {
                quickInput.classList.remove('error');
                const error = document.querySelector('.quick-error');
                if (error) error.remove();
            });

            // Validate on blur
            quickInput.addEventListener('blur', () => {
                if (quickInput.value && !validateFileId(quickInput.value)) {
                    quickInput.classList.add('error');
                }
            });
        }

        // Auto-fill from URL hash
        window.addEventListener('load', () => {
            const hash = window.location.hash.substring(1);
            if (hash && /^[a-f0-9]{8,}$/i.test(hash) && quickInput) {
                quickInput.value = hash;
            }
        });
    }

    // Listen for system theme changes
    function initSystemThemeListener() {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

        const handleSystemThemeChange = (e) => {
            // Only change if user hasn't set a preference
            if (!localStorage.getItem(THEME_KEY)) {
                const theme = e.matches ? 'dark' : 'light';
                applyTheme(theme);
                updateThemeToggle(theme);
            }
        };

        mediaQuery.addEventListener('change', handleSystemThemeChange);
    }

    // Initialize all functionality
    function init() {
        // Initialize theme
        initTheme();
        initSystemThemeListener();

        // Initialize navigation
        initMobileNav();
        initSmoothScroll();
        initQuickDownload();

        // Add theme toggle event listener
        const themeToggle = document.querySelector('#themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', toggleTheme);

            // Handle keyboard navigation
            themeToggle.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleTheme();
                }
            });
        }

        // Add loading state to buttons
        document.addEventListener('click', (e) => {
            if (e.target.matches('.btn, .share-btn')) {
                const btn = e.target;
                const originalText = btn.innerHTML;

                // Only show loading for actions that might take time
                if (btn.type === 'submit' || btn.classList.contains('download-btn')) {
                    btn.classList.add('loading');
                    btn.disabled = true;

                    // Reset after 3 seconds (fallback)
                    setTimeout(() => {
                        btn.classList.remove('loading');
                        btn.disabled = false;
                        btn.innerHTML = originalText;
                    }, 3000);
                }
            }
        });

        // Add CSS for loading state if not already present
        if (!document.querySelector('#loading-styles')) {
            const style = document.createElement('style');
            style.id = 'loading-styles';
            style.textContent = `
                .btn.loading::after,
                .share-btn.loading::after {
                    content: '';
                    position: absolute;
                    width: 20px;
                    height: 20px;
                    border: 2px solid rgba(255, 255, 255, 0.3);
                    border-top-color: white;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                }
                
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
                
                .quick-error {
                    background: linear-gradient(135deg, #ff5252, #ff4081);
                    color: white;
                    padding: 10px 15px;
                    border-radius: 8px;
                    margin: 10px 0;
                    animation: slideIn 0.3s ease;
                }
                
                @keyframes slideIn {
                    from {
                        opacity: 0;
                        transform: translateY(-10px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
            `;
            document.head.appendChild(style);
        }

        // Dispatch loaded event
        document.dispatchEvent(new CustomEvent('securefileshare:loaded'));
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();