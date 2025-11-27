# EasyWebDAV-PHP 🚀

[![PHP Version](https://img.shields.io/badge/php-5.6%20--%208.4-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**EasyWebDAV** is an ultimate, lightweight, single-file WebDAV server and file manager for PHP. Designed for shared hosting and virtual environments, it requires no database and is ready to deploy instantly.

It features a unique **"Hidden Path" security mechanism**, where the script filename itself acts as the access gateway, preventing unauthorized directory scanning.

---

## ✨ Key Features

*   **🔒 Strict Path Security**: Access is only possible via the exact script filename. Direct directory access results in a 403 Forbidden error.
*   **📂 Full WebDAV Support**: Compatible with Windows Explorer, macOS Finder, iOS (Documents, Files), and Android clients.
*   **☁️ Unlimited Uploads**: No code-level file size limits (supports large file transfers depending on server config).
*   **🛡️ Auto-Hardening**: Automatically generates `.htaccess` rules to prevent directory traversal and disable PHP execution in the storage folder (Anti-Webshell).
*   **🎨 Modern UI**: Built-in responsive HTML5 file manager with drag-and-drop upload, folder creation, and file previews.
*   **🚀 Broad Compatibility**: Works on PHP 5.6 through 8.4. 

---

## 🛠️ Installation & Deployment

### 1. Download
Download the `easywebdav.php` file (or whatever you named the script) to your local machine.

### 2. Rename (Security Best Practice)
To utilize the Hidden Path mechanism effectively, rename the file to something unique.
*   ❌ `webdav.php` (Too obvious)
*   ✅ `my_disk.php`
*   ✅ `x9s2a.php`

### 3. Upload
Upload the file to any directory on your PHP/Apache server (e.g., `/disk/`).

### 4. Initialize
Visit the **full path** of the file in your browser:
```text
http://your-domain.com/disk/x9s2a.php
```
> **Note**: If you try to visit `http://your-domain.com/disk/`, you will see a **403 Forbidden** error. This is a security feature. You must include the filename.

### 5. Setup Credentials
On the first visit, you will be prompted to set a **Username** and **Password**. Once saved, you will be redirected to the file manager.

---

## 📡 WebDAV Connection Guide

You can connect to this server using any WebDAV-compatible client.

**Connection Parameters:**

*   **Server URL:** `http://your-domain.com/disk/x9s2a.php`
    *   *Important: You must include the `.php` extension in the URL.*
*   **Username:** The username you set during setup.
*   **Password:** The password you set during setup.

### Client Examples

*   **Windows (Map Network Drive)**:
    1.  Open "This PC" -> "Map network drive".
    2.  Folder: `http://your-domain.com/disk/x9s2a.php`.
    3.  Check "Connect using different credentials".

*   **iOS (Documents by Readdle / Files App)**:
    1.  Add Connection -> WebDAV Server.
    2.  URL: `http://your-domain.com/disk/x9s2a.php`.

*   **macOS Finder**:
    1.  Go -> Connect to Server (Cmd+K).
    2.  Address: `http://your-domain.com/disk/x9s2a.php`.

---

## 🔒 Security Architecture

EasyWebDAV employs a multi-layered defense strategy:

1.  **Strict Path Mode**:
    The script validates the `Base URI`. If a user or scanner tries to access the root folder or use `../` traversal, the request is rejected. The filename effectively acts as a "second password."

2.  **Anti-Webshell Protection**:
    The script automatically creates an `.htaccess` file in the `storage/` directory. It forces `php_flag engine off` and `RemoveHandler .php`, ensuring that even if an attacker uploads a malicious PHP file, they cannot execute it via the browser.

3.  **CGI/FastCGI Auth Fix**:
    Many shared hosts run PHP in CGI mode, which strips the `Authorization` header, causing an infinite login loop. This script includes specific `.htaccess` rewrite rules and PHP logic to manually recover the credentials from the environment variables.

4.  **System File Hiding**:
    Access to sensitive files like `.htpasswd.php`, `.htaccess`, and the script itself is blocked at the code level.

---

## 📋 Requirements

*   **Server**: Apache (Required for `.htaccess` rules to work).
*   **PHP Version**: 5.6, 7.x, 8.0 - 8.4.
*   **Permissions**: The directory containing the script must be writable (755 or 777) so the script can create the `storage` folder and configuration files.

---

## ⚠️ Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. The author is not responsible for any data loss or security issues that may arise from the use of this software. Please backup your data regularly.

---

Copyright © 2025 Prince.
