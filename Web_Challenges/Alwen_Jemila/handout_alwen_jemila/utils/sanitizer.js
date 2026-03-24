function sanitizeCSS(css) {
    if (typeof css !== 'string') return '';

    let sanitized = css;

    sanitized = sanitized.replace(/<\s*\/?style[^>]*/gi, '/* blocked */');
    sanitized = sanitized.replace(/<[^>]*>/g, '/* blocked */');
    sanitized = sanitized.replace(/@import\b[^;]*/gi, '/* blocked */');
    sanitized = sanitized.replace(/@font-face\s*\{[^}]*\}/gi, '/* blocked */');
    sanitized = sanitized.replace(/@namespace\b[^;]*/gi, '/* blocked */');
    sanitized = sanitized.replace(/url\s*\(/gi, '/* blocked */');
    sanitized = sanitized.replace(/expression\s*\(/gi, '/* blocked */');
    sanitized = sanitized.replace(/javascript\s*:/gi, '/* blocked */');
    sanitized = sanitized.replace(/vbscript\s*:/gi, '/* blocked */');
    sanitized = sanitized.replace(/behavior\s*:/gi, '/* blocked */');
    sanitized = sanitized.replace(/-moz-binding\s*:/gi, '/* blocked */');
    sanitized = sanitized.replace(/\\[0-9a-fA-F]{1,6}\s?/g, '/* blocked */');

    sanitized = sanitized.replace(/@import\b[^;]*/gi, '/* blocked */');
    sanitized = sanitized.replace(/@font-face\s*\{[^}]*\}/gi, '/* blocked */');
    sanitized = sanitized.replace(/url\s*\(/gi, '/* blocked */');
    sanitized = sanitized.replace(/expression\s*\(/gi, '/* blocked */');
    sanitized = sanitized.replace(/javascript\s*:/gi, '/* blocked */');
    sanitized = sanitized.replace(/\\[0-9a-fA-F]{1,6}\s?/g, '/* blocked */');

    sanitized = sanitized.replace(/url\s*\(/gi, '/* blocked */');

    if (sanitized.length > 10000) {
        return '/* CSS too long */';
    }

    return sanitized;
}

module.exports = { sanitizeCSS };
