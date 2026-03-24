document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    initNavToggle();
    initFlashAutoDismiss();
    initShareButtons();
});

function initParticles() {
    const container = document.getElementById('particles');
    if (!container) return;

    const count = 40;
    for (let i = 0; i < count; i++) {
        const p = document.createElement('div');
        p.classList.add('particle');
        p.style.left = Math.random() * 100 + '%';
        p.style.animationDelay = Math.random() * 8 + 's';
        p.style.animationDuration = 6 + Math.random() * 6 + 's';

        const size = 1 + Math.random() * 3;
        p.style.width = size + 'px';
        p.style.height = size + 'px';

        const hue = 250 + Math.random() * 120;
        p.style.background = `hsl(${hue}, 70%, 65%)`;
        p.style.boxShadow = `0 0 ${4 + Math.random() * 8}px hsl(${hue}, 70%, 65%)`;

        container.appendChild(p);
    }
}

function initNavToggle() {
    const toggle = document.getElementById('navToggle');
    if (!toggle) return;

    toggle.addEventListener('click', () => {
        const links = document.querySelector('.nav-links');
        if (links) {
            links.classList.toggle('open');
        }
    });
}

function initFlashAutoDismiss() {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            flash.style.transform = 'translateX(30px)';
            setTimeout(() => flash.remove(), 300);
        }, 5000);
    });
}

function initShareButtons() {
    document.querySelectorAll('.copy-share-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const url = btn.dataset.shareUrl;
            try {
                await navigator.clipboard.writeText(url);
                const original = btn.innerHTML;
                btn.innerHTML = '✓ Copied!';
                btn.style.color = 'var(--success)';
                setTimeout(() => {
                    btn.innerHTML = original;
                    btn.style.color = '';
                }, 2000);
            } catch {
                const textarea = document.createElement('textarea');
                textarea.value = url;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                btn.innerHTML = '✓ Copied!';
                setTimeout(() => {
                    btn.innerHTML = '🔗 Share';
                }, 2000);
            }
        });
    });
}
