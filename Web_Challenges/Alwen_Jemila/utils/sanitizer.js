/**
 * CSS Sanitizer - ChromaLeak
 * 
 * Sanitizes user-provided CSS to prevent malicious injections.
 * Uses multi-pass regex filtering to block known attack vectors.
 */

function sanitizeCSS(css) {
    if (typeof css !== 'string') return '';
    
    let sanitized = css;

    // ===== PASS 1: Core sanitization =====

    // Prevent <style> tag escape
    sanitized = sanitized.replace(/<\s*\/?style[^>]*/gi, '/* blocked */');

    // Block HTML tags entirely
    sanitized = sanitized.replace(/<[^>]*>/g, '/* blocked */');

    // Block @import rules
    sanitized = sanitized.replace(/@import\b[^;]*/gi, '/* blocked */');

    // Block @font-face blocks
    sanitized = sanitized.replace(/@font-face\s*\{[^}]*\}/gi, '/* blocked */');

    // Block @namespace
    sanitized = sanitized.replace(/@namespace\b[^;]*/gi, '/* blocked */');

    // Block url() function - primary exfiltration vector
    sanitized = sanitized.replace(/url\s*\(/gi, '/* blocked */');

    // Block expression() - IE CSS expressions
    sanitized = sanitized.replace(/expression\s*\(/gi, '/* blocked */');

    // Block javascript: protocol
    sanitized = sanitized.replace(/javascript\s*:/gi, '/* blocked */');

    // Block vbscript: protocol
    sanitized = sanitized.replace(/vbscript\s*:/gi, '/* blocked */');

    // Block behavior property (IE)
    sanitized = sanitized.replace(/behavior\s*:/gi, '/* blocked */');

    // Block -moz-binding (Firefox XBL)
    sanitized = sanitized.replace(/-moz-binding\s*:/gi, '/* blocked */');

    // Block CSS hex escape sequences (\XX, \XXXX, \XXXXXX)
    // This prevents bypass via \75 (u), \72 (r), \6c (l), etc.
    sanitized = sanitized.replace(/\\[0-9a-fA-F]{1,6}\s?/g, '/* blocked */');

    // ===== PASS 2: Defense in depth =====
    // Second pass to catch any payloads reconstructed after first pass

    sanitized = sanitized.replace(/@import\b[^;]*/gi, '/* blocked */');
    sanitized = sanitized.replace(/@font-face\s*\{[^}]*\}/gi, '/* blocked */');
    sanitized = sanitized.replace(/url\s*\(/gi, '/* blocked */');
    sanitized = sanitized.replace(/expression\s*\(/gi, '/* blocked */');
    sanitized = sanitized.replace(/javascript\s*:/gi, '/* blocked */');
    sanitized = sanitized.replace(/\\[0-9a-fA-F]{1,6}\s?/g, '/* blocked */');

    // ===== PASS 3: Final validation =====
    // Ensure no url() slipped through via any encoding tricks
    sanitized = sanitized.replace(/url\s*\(/gi, '/* blocked */');

    // Length limit per CSS block
    if (sanitized.length > 10000) {
        return '/* CSS too long */';
    }

    return sanitized;
}

module.exports = { sanitizeCSS };
