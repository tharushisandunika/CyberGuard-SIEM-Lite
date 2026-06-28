/**
 * Authentication and Session Manager for CyberGuard SIEM
 */

function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (e) {
        return null;
    }
}

const Auth = {
    getToken: () => {
        return localStorage.getItem('token');
    },

    setToken: (token) => {
        localStorage.setItem('token', token);
    },

    clearToken: () => {
        localStorage.removeItem('token');
    },

    getHeaders: () => {
        const token = Auth.getToken();
        return {
            'Content-Type': 'application/json',
            'Authorization': token ? `Bearer ${token}` : ''
        };
    },

    getUser: () => {
        const token = Auth.getToken();
        if (!token) return null;
        const payload = parseJwt(token);
        // Flask-JWT-Extended encapsulates identity inside 'sub' or 'fresh' depending on setup
        // We set identity=identity in create_access_token, so it is in payload['sub']
        return payload ? payload.sub : null;
    },

    isAuthenticated: () => {
        const token = Auth.getToken();
        if (!token) return false;
        
        // Check expiration
        const payload = parseJwt(token);
        if (!payload) return false;
        
        const now = Math.floor(Date.now() / 1000);
        return payload.exp > now;
    },

    logout: async () => {
        try {
            // Trigger backend logout to register audit trace
            const headers = Auth.getHeaders();
            await fetch('/api/auth/logout', { 
                method: 'POST', 
                headers: headers 
            });
        } catch (e) {
            console.error("Auth logout endpoint error:", e);
        } finally {
            Auth.clearToken();
            window.location.href = '/login';
        }
    },

    checkSession: () => {
        const path = window.location.pathname;
        const isAuth = Auth.isAuthenticated();

        if (path === '/login') {
            if (isAuth) {
                window.location.href = '/';
            }
        } else {
            if (!isAuth) {
                Auth.clearToken();
                window.location.href = '/login';
            }
        }
    }
};

// Auto run session checks on file mount
Auth.checkSession();
