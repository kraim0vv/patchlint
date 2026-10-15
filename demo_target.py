"""Lightweight vulnerable test server for local testing of PatchLint DAST.

Uses Python's standard library http.server (NO external dependencies required).
Run with:
    python demo_target.py
Then audit it with:
    patchlint http://127.0.0.1:8888
"""

import http.server
import socketserver
import sys

PORT = 8888


class VulnerableServerHandler(http.server.SimpleHTTPRequestHandler):
    """Simulates typical developer misconfigurations and file leaks."""

    def version_string(self) -> str:
        # Deliberately expose verbose server banner
        return "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"

    def end_headers(self) -> None:
        # Deliberately disclose technology stack
        self.send_header("X-Powered-By", "PHP/8.1.0")
        # Intentionally OMIT CSP, HSTS, X-Frame-Options, X-Content-Type-Options
        super().end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/.env":
            content = (
                "APP_ENV=local\n"
                "APP_KEY=base64:Jq4v9bXy1kLz8nQ2mP0oR7sT5uVw3xYzA=\n"
                "DB_CONNECTION=mysql\n"
                "DB_HOST=127.0.0.1\n"
                "DB_PORT=3306\n"
                "DB_DATABASE=app_production\n"
                "DB_USERNAME=root\n"
                "DB_PASSWORD=SuperSecretPass123!\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/.git/HEAD":
            content = b"ref: refs/heads/main\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/docker-compose.yml":
            content = (
                "version: '3.8'\n"
                "services:\n"
                "  web:\n"
                "    image: nginx:alpine\n"
                "    ports:\n"
                "      - '80:80'\n"
                "  db:\n"
                "    image: postgres:14\n"
                "    environment:\n"
                "      POSTGRES_PASSWORD: admin\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/config.json":
            content = (
                '{\n'
                '  "app": "Internal API",\n'
                '  "database": {\n'
                '    "host": "localhost",\n'
                '    "password": "dev_db_password"\n'
                '  }\n'
                '}'
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path == "/dump.sql":
            content = (
                "-- MySQL dump 10.13\n"
                "CREATE TABLE `users` (\n"
                "  `id` int(11) NOT NULL,\n"
                "  `email` varchar(255) NOT NULL,\n"
                "  `password_hash` varchar(255) NOT NULL\n"
                ");\n"
                "INSERT INTO `users` VALUES (1, 'admin@corp.local', '$2y$10$e8...');\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/sql")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
        if path in ("/openapi.json", "/swagger.json"):
            content = (
                '{\n'
                '  "openapi": "3.0.0",\n'
                '  "info": {\n'
                '    "title": "Vulnerable Demo API",\n'
                '    "version": "1.0.0"\n'
                '  },\n'
                '  "paths": {\n'
                '    "/api/users": {\n'
                '      "get": {"summary": "List all users"}\n'
                '    }\n'
                '  }\n'
                '}'
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if "_patchlint_debug_probe" in path or path == "/debug":
            content = (
                "<html><head><title>500 Internal Error</title></head><body>\n"
                "<h1>Traceback (most recent call last):</h1>\n"
                "<div class='traceback'>Werkzeug Powered Traceback</div>\n"
                "<p>The debugger caught an exception in your WSGI application.</p>\n"
                "</body></html>"
            ).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # Default home page
        content = (
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head><title>Demo Web App</title></head>\n"
            "<body>\n"
            "  <h1>Welcome to Demo App</h1>\n"
            "  <p>This is a local staging server for security testing.</p>\n"
            "</body>\n"
            "</html>\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), VulnerableServerHandler) as httpd:
        print(f"[+] Vulnerable Demo Server listening on http://127.0.0.1:{PORT}")
        print("[+] Press Ctrl+C to terminate.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down test server.")
            httpd.server_close()


if __name__ == "__main__":
    main()
