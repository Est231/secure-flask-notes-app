class EnhancedSecurityHeaders:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, response_headers, exc_info=None):
            # ПРИМЕНЯЕМ КО ВСЕМ СТАТУСАМ (200, 404, 500, и т.д.)
            filtered_headers = []
            security_headers_to_remove = [
                'content-security-policy',
                'x-content-type-options',
                'x-frame-options',
                'x-xss-protection',
                'referrer-policy',
                'permissions-policy',
                'server',
                'strict-transport-security'
            ]

            for header_name, header_value in response_headers:
                if header_name.lower() not in security_headers_to_remove:
                    if header_name.lower() == 'set-cookie':
                        if 'samesite' not in header_value.lower():
                            header_value += '; SameSite=Lax'
                        if 'httponly' not in header_value.lower():
                            header_value += '; HttpOnly'
                    filtered_headers.append((header_name, header_value))

            # ВАЖНО: Применяем ко всем ответам (включая ошибки)
            new_security_headers = [
                ('Content-Security-Policy',
                 "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none';"),
                ('X-Content-Type-Options', 'nosniff'),  #  ДОЛЖЕН БЫТЬ ВСЕГДА
                ('X-Frame-Options', 'DENY'),
                ('X-XSS-Protection', '1; mode=block'),
                ('Referrer-Policy', 'strict-origin-when-cross-origin'),
                ('Server', 'Unknown'),
            ]

            final_headers = new_security_headers + filtered_headers

            # Логируем для отладки
            print(f"🔧 Applying security headers for status: {status}")

            return start_response(status, final_headers, exc_info)

        return self.app(environ, custom_start_response)