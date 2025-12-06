# EasyWebDAV-PHP

A single-file PHP **WebDAV** server with a modern **web file manager**, **HTTP Basic Auth**, **share links**, and optional **operation logs**.

## Requirements

* PHP 7.4+ (PHP 8.x recommended)
* Web server: **Apache** recommended (the script auto-generates `.htaccess` rules)

## Features

* **HTTP Basic Authentication** (stored hashed in `/.htpasswd.php`)
* **WebDAV methods**: `OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, MOVE, LOCK, UNLOCK`
* **Web UI**:

  * Upload files
  * Create folders
  * Rename / Copy / Move / Delete
  * Download files
  * Share management
  * Dark mode + CN/EN language switch
* **Share links**:

  * `/s/<token>` or `?s=<token>`
  * Supports **expiration** and **max uses**
  * Stored in `/.shares.php`
* **Logging (optional)**:

  * Daily logs in `./logs/YYYY-MM-DD.log`
  * Download/clear from the UI (`?log_action=download` / `?log_action=clear`)

## Quick Start (Apache)

1. Upload `index.php` to your site directory (e.g. `public_html/`).
2. Visit it in a browser.
3. On first run, the script will prompt for **Basic Auth** — the first successful credentials are saved to `/.htpasswd.php`.
4. Your files are stored in `./storage/`.

### WebDAV URL

Use your WebDAV client with:

* `http(s)://<host>/<path-to-index.php>/`

(Authenticate with the same Basic Auth username/password.)

## Configuration

Edit constants at the top of the script:

* `LOG_ENABLED` (default `true`)
* `LOG_PATH` (default `./logs`)
* Storage path is `./storage` (constant `S_PATH`)

## Notes / Tips

* **Use HTTPS** when possible (Basic Auth over plain HTTP is not encrypted).
* If you use **Nginx/Caddy**, `.htaccess` is ignored—make sure your server config blocks direct access to:

  * `/.htpasswd.php`, `/.shares.php`, `./logs/`, and `./storage/` (as needed)
* If you ever delete `/.htpasswd.php`, the script will enter setup mode again and accept a new first-login credential.
