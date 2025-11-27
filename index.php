<?php
/**
 * EasyWebDAV - Single File WebDAV Server & File Manager
 * Optimized for UI/UX and Performance
 * By Prince | https://github.com/Andeasw/EasyWebDAV-PHP
 */
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(true);
date_default_timezone_set('PRC');

// --- Session & CSRF Init ---
// 必须在输出任何内容前开启 Session 以存储 Token
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// --- Configuration & Constants ---
define('ROOT_DIR', __DIR__);
define('SCRIPT_NAME', basename($_SERVER['SCRIPT_NAME']));
$scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? "https" : "http";
define('BASE_URL', $scheme . "://" . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']);
define('STORAGE_NAME', 'storage');
define('STORAGE_PATH', ROOT_DIR . DIRECTORY_SEPARATOR . STORAGE_NAME);
define('AUTH_FILE', ROOT_DIR . DIRECTORY_SEPARATOR . '.htpasswd.php');
define('SHARES_FILE', ROOT_DIR . DIRECTORY_SEPARATOR . '.shares.php');

// Protect system files
define('PROTECTED_FILES', serialize(['.', '..', '.htaccess', '.htpasswd', '.htpasswd.php', '.shares.php', SCRIPT_NAME, basename(__FILE__)]));

// --- Language Definitions ---
$langs = [
    'cn' => ['home' => '首页', 'back' => '返回上级', 'upload' => '上传文件', 'new_folder' => '新建文件夹', 'create' => '创建', 'name' => '名称', 'size' => '大小', 'modified' => '修改时间', 'actions' => '操作', 'view' => '浏览', 'download' => '下载', 'rename' => '重命名', 'copy' => '复制', 'move' => '移动', 'delete' => '删除', 'share' => '分享', 'empty' => '目录为空', 'title' => 'EasyWebDAV', 'del_confirm' => '确认删除文件/文件夹', 'share_title' => '文件分享', 'share_link' => '直链地址', 'del_share' => '取消分享', 'copy_link' => '复制链接', 'copied' => '已复制!', 'cancel' => '取消', 'ok' => '确定', 'target_path' => '目标路径 (例如 /work/docs)', 'dark_mode' => '暗黑模式'],
    'en' => ['home' => 'Home', 'back' => 'Back', 'upload' => 'Upload File', 'new_folder' => 'New Folder', 'create' => 'Create', 'name' => 'Name', 'size' => 'Size', 'modified' => 'Modified', 'actions' => 'Actions', 'view' => 'View', 'download' => 'Download', 'rename' => 'Rename', 'copy' => 'Copy', 'move' => 'Move', 'delete' => 'Delete', 'share' => 'Share', 'empty' => 'Directory is empty', 'title' => 'EasyWebDAV', 'del_confirm' => 'Are you sure you want to delete', 'share_title' => 'File Share', 'share_link' => 'Share Link', 'del_share' => 'Delete Share', 'copy_link' => 'Copy Link', 'copied' => 'Copied!', 'cancel' => 'Cancel', 'ok' => 'OK', 'target_path' => 'Target path (e.g. /work/docs)', 'dark_mode' => 'Dark Mode']
];

// --- Language Handling ---
$currLang = $_COOKIE['lang'] ?? 'cn';
if (isset($_GET['lang']) && in_array($_GET['lang'], ['cn', 'en'])) {
    $currLang = $_GET['lang'];
    setcookie('lang', $currLang, time() + 86400 * 365);
    header("Location: " . BASE_URL); exit;
}
function L($k) { global $langs, $currLang; return $langs[$currLang][$k] ?? $k; }

// --- Public Share Handling (No CSRF needed here, pure GET) ---
if (isset($_GET['s'])) {
    if (file_exists(SHARES_FILE)) {
        $shares = include SHARES_FILE;
        if (is_array($shares) && isset($shares[$_GET['s']])) {
            $file = STORAGE_PATH . DIRECTORY_SEPARATOR . $shares[$_GET['s']];
            if (file_exists($file) && is_file($file)) {
                $handler = new DavHandler(); 
                header('Content-Type: ' . $handler->getMimeType($file));
                header('Content-Disposition: attachment; filename="'.basename($file).'"');
                header('Content-Length: ' . filesize($file));
                readfile($file); exit;
            }
        }
    }
    http_response_code(404); die('Link Expired or File Not Found');
}

// --- Initialization & Auth ---
if (!file_exists(STORAGE_PATH)) @mkdir(STORAGE_PATH, 0755, true);
if (!file_exists(STORAGE_PATH . '/.htaccess')) @file_put_contents(STORAGE_PATH . '/.htaccess', "Deny from all");
if (!file_exists(ROOT_DIR . '/.htaccess')) @file_put_contents(ROOT_DIR . '/.htaccess', "Options -Indexes\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n</IfModule>\n");

// Basic Auth Logic
if (empty($_SERVER['PHP_AUTH_USER'])) {
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    if ($h && preg_match('/Basic\s+(.*)$/i', $h, $m)) {
        list($u, $p) = explode(':', base64_decode($m[1]), 2);
        $_SERVER['PHP_AUTH_USER'] = $u; $_SERVER['PHP_AUTH_PW'] = $p;
    }
}
if (!file_exists(AUTH_FILE)) {
    if (!empty($_SERVER['PHP_AUTH_USER']) && !empty($_SERVER['PHP_AUTH_PW'])) {
        $hash = password_hash($_SERVER['PHP_AUTH_PW'], PASSWORD_DEFAULT);
        $data = "<?php return " . var_export(['u' => $_SERVER['PHP_AUTH_USER'], 'h' => $hash], true) . ";";
        @file_put_contents(AUTH_FILE, $data);
    } else {
        header('WWW-Authenticate: Basic realm="Install: Enter Admin Username/Password"');
        header('HTTP/1.0 401 Unauthorized');
        die('Setup Required: Please login with desired username and password to initialize.');
    }
}
$auth = include AUTH_FILE;
if (empty($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER'] !== $auth['u'] || !password_verify($_SERVER['PHP_AUTH_PW'], $auth['h'])) {
    header('WWW-Authenticate: Basic realm="EasyWebDAV"');
    header('HTTP/1.0 401 Unauthorized');
    die('Access Denied');
}

// --- Main Request Handling ---
$server = new DavHandler();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Route POST requests to Browser Handlers (These need CSRF checks)
    if (isset($_FILES['file'])) $server->handleBrowserUpload();
    else if (isset($_POST['mkdir'])) $server->handleBrowserMkdir();
    else if (isset($_POST['action'])) $server->handleBrowserAction();
    else if (isset($_POST['share_action'])) $server->handleShareAction();
    else $server->serve(); // Fallback
} else {
    // Standard WebDAV methods (GET, PUT, DELETE, PROPFIND) - No CSRF check needed for protocol clients
    $server->serve();
}

// --- Logic Class ---
class DavHandler {
    private $baseUri, $reqPath, $fsPath, $protect;

    public function __construct() {
        $this->protect = unserialize(PROTECTED_FILES);
        $this->parsePath();
    }

    private function parsePath() {
        $this->baseUri = $_SERVER['SCRIPT_NAME']; 
        $uri = rawurldecode(explode('?', $_SERVER['REQUEST_URI'])[0]);
        if (strpos($uri, $this->baseUri) === 0) {
            $rel = substr($uri, strlen($this->baseUri));
        } else {
            $rel = $uri; 
        }
        $this->reqPath = empty($rel) ? '/' : $rel;
        
        $parts = [];
        foreach (explode('/', str_replace('\\', '/', $this->reqPath)) as $p) {
            if ($p === '' || $p === '.') continue;
            if ($p === '..') array_pop($parts); else $parts[] = $p;
        }
        $this->fsPath = STORAGE_PATH . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
    }

    // --- CSRF Protection Logic ---
    private function checkCsrf() {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            header('HTTP/1.1 403 Forbidden');
            die('Security Error: Invalid CSRF Token. Please refresh the page.');
        }
    }

    public function serve() {
        try {
            $method = $_SERVER['REQUEST_METHOD'];
            switch ($method) {
                case 'GET': $this->doGet(); break;
                case 'PUT': $this->doPut(); break;
                case 'PROPFIND': $this->doPropfind(); break;
                case 'OPTIONS': $this->doOptions(); break;
                case 'DELETE': $this->doDelete(); break;
                case 'MKCOL': $this->doMkcol(); break;
                case 'COPY': $this->doCopyMove(false); break;
                case 'MOVE': $this->doCopyMove(true); break;
                case 'HEAD': $this->doHead(); break;
                case 'LOCK': $this->doLock(); break;
                case 'UNLOCK': $this->doUnlock(); break;
                default: http_response_code(405); break;
            }
        } catch (Exception $e) { http_response_code(500); }
    }

    // ... (Standard WebDAV methods omit CSRF check to support clients like OpenList) ...
    private function doOptions() { 
        header('DAV: 1, 2'); 
        header('Allow: OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, MKCOL, COPY, MOVE, LOCK, UNLOCK'); 
        header('MS-Author-Via: DAV'); 
        exit; 
    }
    
    private function doGet() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        if (is_dir($this->fsPath)) { $this->sendHtml(); exit; }
        if ($this->isProtected(basename($this->fsPath))) { http_response_code(404); exit; }
        $size = filesize($this->fsPath);
        $isDownload = isset($_GET['download']) && $_GET['download'] == 1;
        $mime = $this->getMimeType($this->fsPath);
        header('Content-Type: ' . ($isDownload ? 'application/octet-stream' : $mime));
        header('Content-Length: ' . $size);
        header('ETag: "' . md5($this->fsPath . $size . filemtime($this->fsPath)) . '"');
        header('Content-Disposition: ' . ($isDownload ? 'attachment' : 'inline') . '; filename="'.basename($this->fsPath).'"');
        while (ob_get_level()) ob_end_clean();
        $fp = fopen($this->fsPath, 'rb'); fpassthru($fp); fclose($fp); exit;
    }

    private function doPut() {
        if ($this->isProtected(basename($this->fsPath))) { http_response_code(403); exit; }
        $dir = dirname($this->fsPath); if (!is_dir($dir)) mkdir($dir, 0755, true);
        $in = fopen('php://input', 'rb'); $out = fopen($this->fsPath, 'wb');
        if ($in && $out) { stream_copy_to_stream($in, $out); http_response_code(201); } else http_response_code(500);
        @fclose($in); @fclose($out);
    }

    private function doPropfind() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        $depth = isset($_SERVER['HTTP_DEPTH']) ? (int)$_SERVER['HTTP_DEPTH'] : 1;
        header('HTTP/1.1 207 Multi-Status'); header('Content-Type: application/xml; charset="utf-8"');
        echo '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
        $files = is_dir($this->fsPath) ? array_merge([$this->fsPath], ($depth !== 0 ? glob($this->fsPath.'/*', GLOB_NOSORT) : [])) : [$this->fsPath];
        foreach ($files as $f) {
            if ($this->isProtected(basename($f))) continue;
            $rel = substr($f, strlen(STORAGE_PATH));
            $rel = str_replace('\\', '/', $rel);
            $href = $this->baseUri . implode('/', array_map('rawurlencode', explode('/', $rel)));
            $stat = stat($f);
            echo '<D:response><D:href>' . $href . '</D:href><D:propstat><D:prop><D:displayname>' . htmlspecialchars(basename($f)) . '</D:displayname><D:getlastmodified>' . gmdate('D, d M Y H:i:s T', $stat['mtime']) . '</D:getlastmodified>';
            if (is_dir($f)) echo '<D:resourcetype><D:collection/></D:resourcetype>';
            else { echo '<D:resourcetype/><D:getcontentlength>' . sprintf('%u', $stat['size']) . '</D:getcontentlength>'; }
            echo '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
        }
        echo '</D:multistatus>';
    }

    private function doDelete() { 
        if (!file_exists($this->fsPath) || $this->fsPath == STORAGE_PATH) { http_response_code(403); exit; } 
        $this->rm($this->fsPath); http_response_code(204); 
    }

    private function doMkcol() { 
        if (file_exists($this->fsPath)) { http_response_code(405); exit; } 
        mkdir($this->fsPath, 0755, true) ? http_response_code(201) : http_response_code(409); 
    }

    private function doCopyMove($isMove) {
        $dest = $_SERVER['HTTP_DESTINATION'] ?? ''; if (!$dest) { http_response_code(400); exit; }
        $path = rawurldecode(parse_url($dest, PHP_URL_PATH));
        if (strpos($path, SCRIPT_NAME) === false) { http_response_code(502); exit; }
        $relDest = substr($path, strpos($path, SCRIPT_NAME) + strlen(SCRIPT_NAME));
        $target = STORAGE_PATH . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, array_filter(explode('/', $relDest), function($p){ return $p !== '' && $p !== '.' && $p !== '..'; }));
        if ($this->isProtected(basename($target))) { http_response_code(403); exit; }
        if (file_exists($target)) { if (($_SERVER['HTTP_OVERWRITE'] ?? 'T') === 'F') { http_response_code(412); exit; } $this->rm($target); }
        if ($isMove) rename($this->fsPath, $target) ? http_response_code(201) : http_response_code(500);
        else { $this->cp($this->fsPath, $target); http_response_code(201); }
    }

    private function doLock() { $t = 'urn:uuid:' . uniqid(); header('Content-Type: application/xml; charset="utf-8"'); header('Lock-Token: <' . $t . '>'); echo '<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>Infinity</D:depth><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>'.$t.'</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>'; exit; }

    private function doUnlock() { http_response_code(204); }
    private function doHead() { file_exists($this->fsPath) ? http_response_code(200) : http_response_code(404); }

    // --- Browser Action Handlers (WITH CSRF PROTECTION) ---

    public function handleBrowserUpload() {
        $this->checkCsrf();
        if (is_dir($this->fsPath) && $_FILES['file']['error'] == 0) {
            $n = basename($_FILES['file']['name']);
            if (!$this->isProtected($n)) move_uploaded_file($_FILES['file']['tmp_name'], $this->fsPath . DIRECTORY_SEPARATOR . $n);
        } 
        $this->redirectBack();
    }

    public function handleBrowserMkdir() {
        $this->checkCsrf();
        $n = str_replace(['/', '\\'], '', trim($_POST['mkdir']));
        if ($n && !$this->isProtected($n)) @mkdir($this->fsPath . DIRECTORY_SEPARATOR . $n);
        $this->redirectBack();
    }

    public function handleBrowserAction() {
        $this->checkCsrf();
        $action = $_POST['action'] ?? ''; $name = $_POST['name'] ?? ''; $newname = $_POST['newname'] ?? ''; $target = $_POST['target'] ?? '';
        if (!$name || $this->isProtected($name)) { $this->redirectBack(); return; }
        $curr = $this->fsPath; $item = $curr . DIRECTORY_SEPARATOR . $name;
        switch ($action) {
            case 'rename': 
                $n = str_replace(['/', '\\'], '', trim($newname));
                if ($n && !$this->isProtected($n)) rename($item, $curr . DIRECTORY_SEPARATOR . $n); 
                break;
            case 'delete': 
                if (file_exists($item) && $item != STORAGE_PATH) $this->rm($item); 
                break;
            case 'copy': 
                if ($target) {
                    $d = STORAGE_PATH . DIRECTORY_SEPARATOR . ltrim($target, '/') . DIRECTORY_SEPARATOR . $name;
                    if(!$this->isProtected(basename($target))) $this->cp($item, $d);
                }
                break;
            case 'move': 
                if ($target) {
                    $d = STORAGE_PATH . DIRECTORY_SEPARATOR . ltrim($target, '/') . DIRECTORY_SEPARATOR . $name;
                    if(!$this->isProtected(basename($target))) rename($item, $d);
                }
                break;
        } 
        $this->redirectBack();
    }

    public function handleShareAction() {
        $this->checkCsrf();
        $name = $_POST['name'] ?? ''; $type = $_POST['share_action'] ?? '';
        $shares = file_exists(SHARES_FILE) ? include SHARES_FILE : []; if (!is_array($shares)) $shares = [];
        if ($type === 'create') {
            $rel = ltrim(substr($this->fsPath . DIRECTORY_SEPARATOR . $name, strlen(STORAGE_PATH)), '/\\');
            foreach ($shares as $k => $v) if ($v === $rel) unset($shares[$k]);
            $shares[bin2hex(random_bytes(8))] = $rel;
        } elseif ($type === 'delete') { 
            if (isset($shares[$_POST['token'] ?? ''])) unset($shares[$_POST['token']]); 
        }
        file_put_contents(SHARES_FILE, "<?php return " . var_export($shares, true) . ";");
        $this->redirectBack();
    }

    private function redirectBack() { header("Location: " . $_SERVER['REQUEST_URI']); exit; }
    private function isProtected($n) { return in_array($n, $this->protect); }
    private function rm($p) { 
        if (is_dir($p)) { 
            foreach(scandir($p) as $i) if ($i !== '.' && $i !== '..') $this->rm($p . DIRECTORY_SEPARATOR . $i); 
            rmdir($p); 
        } else unlink($p); 
    }
    private function cp($s, $d) { 
        if (is_dir($s)) { 
            if (!file_exists($d)) mkdir($d, 0755, true); 
            foreach(scandir($s) as $i) if ($i !== '.' && $i !== '..') $this->cp($s . DIRECTORY_SEPARATOR . $i, $d . DIRECTORY_SEPARATOR . $i); 
        } else copy($s, $d); 
    }
    private function fmt($b) { 
        $u=['B','KB','MB','GB','TB']; $i=0; 
        while($b>=1024&&$i<4){$b/=1024;$i++;} 
        return round($b,2).' '.$u[$i]; 
    }

    public function getMimeType($file) {
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $mimes = [
            'txt' => 'text/plain', 'htm' => 'text/html', 'html' => 'text/html', 'php' => 'text/plain', 
            'css' => 'text/css', 'js' => 'application/javascript', 'json' => 'application/json',
            'xml' => 'application/xml', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
            'gif' => 'image/gif', 'bmp' => 'image/bmp', 'ico' => 'image/x-icon', 'svg' => 'image/svg+xml',
            'webp' => 'image/webp', 'mp3' => 'audio/mpeg', 'wav' => 'audio/wav', 'ogg' => 'audio/ogg',
            'mp4' => 'video/mp4', 'webm' => 'video/webm', 'pdf' => 'application/pdf', 'zip' => 'application/zip',
            'rar' => 'application/x-rar-compressed', '7z' => 'application/x-7z-compressed'
        ];
        return $mimes[$ext] ?? 'application/octet-stream';
    }

    private function sendHtml() {
        if (headers_sent()) return;
        header('Content-Type: text/html; charset=utf-8');
        global $currLang, $csrf_token;
        $list = scandir($this->fsPath);
        usort($list, function($a, $b) { 
            $ad = is_dir($this->fsPath . '/' . $a); $bd = is_dir($this->fsPath . '/' . $b); 
            return ($ad === $bd) ? strcasecmp($a, $b) : ($ad ? -1 : 1); 
        });
        
        $bc = []; $acc = ''; 
        foreach(array_filter(explode('/', $this->reqPath)) as $p) { 
            $acc .= '/' . $p; 
            $bc[] = ['n'=>$p, 'p'=>$this->baseUri . implode('/', array_map('rawurlencode', explode('/', $acc)))]; 
        }
        
        $shares = file_exists(SHARES_FILE) ? include SHARES_FILE : []; 
        $sharesMap = []; 
        if(is_array($shares)) foreach($shares as $t => $p) $sharesMap[$p] = $t;
        // Icons
        $i_file = '<svg class="svg-i" viewBox="0 0 24 24"><path fill="currentColor" d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>';
        $i_folder = '<svg class="svg-i" viewBox="0 0 24 24" style="color:#fbbf24"><path fill="currentColor" d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>';
        $i_dl = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>';
        $i_share = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z"/></svg>';
        $i_edit = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>';
        $i_copy = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>';
        $i_move = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M10 9h4V6h3l-5-5-5 5h3v3zm-1 1H6V7l-5 5 5 5v-3h3v-4zm14 2l-5-5v3h-3v4h3v3l5-5zm-9 3h-4v3H7l5 5 5-5h-3v-3z"/></svg>';
        $i_del = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>';
        ?>
<!DOCTYPE html><html lang="<?php echo $currLang; ?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title><?php echo L('title'); ?></title>
<style>
:root { 
    /* Light Yellow-Green Theme */
    --bg-grad: linear-gradient(135deg, #f7fee7 0%, #ecfdf5 100%); 
    --bg: #ffffff; --text: #1f2937; --border: #e5e7eb; --hover: #f0fdf4; 
    --primary: #10b981; /* Green-500 */
    --primary-dark: #059669; 
    --accent: #84cc16; /* Lime-500 */
    --danger: #ef4444; 
    --shadow: 0 10px 15px -3px rgba(0,0,0,0.05), 0 4px 6px -2px rgba(0,0,0,0.025);
    --card-bg: rgba(255, 255, 255, 0.95);
}
body.dark-mode { 
    /* Dark Grey-Green Theme */
    --bg-grad: linear-gradient(135deg, #064e3b 0%, #111827 100%);
    --bg: #1f2937; --text: #f3f4f6; --border: #374151; --hover: #111827; 
    --primary: #34d399; --primary-dark: #10b981; 
    --accent: #a3e635; --danger: #f87171; 
    --card-bg: rgba(31, 41, 55, 0.95);
}
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg-grad); color: var(--text); min-height: 100vh; transition: background 0.3s, color 0.3s; background-attachment: fixed; }
.container { max-width: 1200px; margin: 20px auto; background: var(--card-bg); border-radius: 16px; box-shadow: var(--shadow); display: flex; flex-direction: column; width: 95%; border: 1px solid var(--border); overflow: hidden; backdrop-filter: blur(5px); }
header { padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.5); }
body.dark-mode header { background: rgba(0,0,0,0.2); }
.crumbs { flex: 1; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; font-size: 16px; }
.crumbs a { text-decoration: none; color: var(--text); font-weight: 500; padding: 4px 8px; border-radius: 6px; transition: 0.2s; }
.crumbs a:hover { background: var(--primary); color: white; }
.bar { padding: 12px 24px; background: var(--hover); border-bottom: 1px solid var(--border); display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
.btn { padding: 8px 16px; border: 1px solid var(--border); background: var(--bg); border-radius: 8px; cursor: pointer; font-size: 14px; color: var(--text); text-decoration: none; display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s; font-weight: 600; user-select: none; box-shadow: 0 1px 2px 0 rgba(0,0,0,0.05); }
.btn:hover { border-color: var(--primary); color: var(--primary); transform: translateY(-1px); box-shadow: 0 2px 4px 0 rgba(0,0,0,0.05); }
.btn-p { background: linear-gradient(to bottom right, var(--primary), var(--primary-dark)); color: white; border: none; }
.btn-p:hover { opacity: 0.9; color: white; border: none; }
.btn-d { color: var(--danger); border-color: transparent; }
.btn-d:hover { background: var(--danger); color: white; border-color: var(--danger); }
.table-wrap { overflow-x: auto; flex: 1; min-height: 300px; }
table { width: 100%; border-collapse: collapse; min-width: 700px; }
th { text-align: left; padding: 16px 20px; color: var(--primary-dark); font-size: 12px; font-weight: 700; text-transform: uppercase; border-bottom: 1px solid var(--border); background: rgba(240, 253, 244, 0.5); letter-spacing: 0.05em; }
body.dark-mode th { background: rgba(6, 78, 59, 0.3); color: var(--primary); }
td { padding: 14px 20px; border-bottom: 1px solid var(--border); font-size: 14px; color: var(--text); vertical-align: middle; }
tr:hover td { background: var(--hover); }
.link { text-decoration: none; color: var(--text); font-weight: 500; display: flex; align-items: center; gap: 12px; transition: 0.2s; }
.link:hover { color: var(--primary); }
.svg-i { width: 24px; height: 24px; color: #9ca3af; flex-shrink: 0; }
.act-grp { display: flex; gap: 4px; justify-content: flex-end; }
.act-btn { padding: 8px; border: none; background: transparent; border-radius: 6px; cursor: pointer; color: #9ca3af; display: flex; align-items: center; position: relative; transition: 0.2s; }
.act-btn svg { width: 18px; height: 18px; }
.act-btn:hover { background: #ecfdf5; color: var(--primary); }
body.dark-mode .act-btn:hover { background: rgba(52, 211, 153, 0.1); }
.act-btn.del:hover { background: #fee2e2; color: var(--danger); }
body.dark-mode .act-btn.del:hover { background: rgba(239, 68, 68, 0.1); }
/* CSS Tooltip */
.act-btn[data-tooltip]:hover::after {
    content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
    background: #1f2937; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; white-space: nowrap;
    opacity: 0; animation: fadeIn 0.2s forwards; pointer-events: none; margin-bottom: 6px; z-index: 10;
}
@keyframes fadeIn { to { opacity: 1; } }
.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.3); z-index: 999; justify-content: center; align-items: center; padding: 20px; box-sizing: border-box; backdrop-filter: blur(4px); }
.modal-box { background: var(--bg); padding: 24px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25); border: 1px solid var(--border); }
.footer { padding: 20px; text-align: center; font-size: 13px; color: #6b7280; background: var(--hover); border-top: 1px solid var(--border); display: flex; justify-content: center; align-items: center; gap: 8px; }
body.dark-mode .footer { color: #9ca3af; }
.gh-icon svg { width: 20px; height: 20px; fill: #6b7280; transition: 0.2s; }
.gh-icon:hover svg { fill: var(--primary); }
/* Theme Toggle */
.theme-toggle { background: none; border: none; cursor: pointer; padding: 8px; border-radius: 50%; color: var(--text); transition: background 0.2s; outline: none; }
.theme-toggle:hover { background: rgba(0,0,0,0.05); }
.lamp-icon { width: 24px; height: 24px; animation: floating 3s ease-in-out infinite; }
.lamp-bulb { fill: transparent; stroke: #6b7280; stroke-width: 2; transition: all 0.3s ease; }
.lamp-glow { fill: #fbbf24; opacity: 0; transition: opacity 0.4s ease; filter: drop-shadow(0 0 4px #fbbf24); }
body.dark-mode .lamp-bulb { stroke: #fbbf24; }
body.dark-mode .lamp-glow { opacity: 1; }
@keyframes floating { 0% { transform: translateY(0px); } 50% { transform: translateY(-4px); } 100% { transform: translateY(0px); } }
@media(max-width:768px){ .container{margin:0;border-radius:0;height:100vh;border:none} .hide-m{display:none} .link{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap} .bar{padding:10px;gap:8px} .btn{padding:6px 10px;font-size:13px} .crumbs{font-size:14px} }
</style></head>
<body><div class="container">
<header>
    <div class="crumbs"><a href="<?php echo $this->baseUri; ?>/"><?php echo L('home'); ?></a><?php foreach($bc as $b) echo ' / <a href="'.$b['p'].'">'.htmlspecialchars($b['n']).'</a>'; ?></div>
    <div style="display:flex;align-items:center;gap:12px;flex-shrink:0">
        <button class="theme-toggle" type="button" onclick="toggleDarkMode()" aria-label="<?php echo L('dark_mode'); ?>" data-tooltip="<?php echo L('dark_mode'); ?>">
            <svg class="lamp-icon" viewBox="0 0 24 24">
                <path class="lamp-bulb" d="M9 21h6v-2H9v2zm3-19C8.14 2 5 5.14 5 9c0 2.38 1.19 4.47 3 5.74V17c0 .55.45 1 1 1h6c.55 0 1-.45 1-1v-2.26c1.81-1.27 3-3.36 3-5.74 0-3.86-3.14-7-7-7z"/>
                <circle class="lamp-glow" cx="12" cy="9" r="3" />
            </svg>
        </button>
        <div style="font-size:14px;font-weight:500"><a href="?lang=cn" style="text-decoration:none;color:<?php echo $currLang=='cn'?'var(--primary)':'#9ca3af';?>">CN</a> <span style="color:var(--border)">|</span> <a href="?lang=en" style="text-decoration:none;color:<?php echo $currLang=='en'?'var(--primary)':'#9ca3af';?>">EN</a></div>
    </div>
</header>
<div class="bar">
    <?php if($this->reqPath!=='/'): $pp=array_filter(explode('/',$this->reqPath));array_pop($pp); ?><a href="<?php echo $this->baseUri.'/'.implode('/',array_map('rawurlencode',$pp)); ?>" class="btn"><?php echo L('back'); ?></a><?php endif; ?>
    <form method="post" enctype="multipart/form-data" style="margin:0">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <label class="btn btn-p"><?php echo L('upload'); ?><input type="file" name="file" hidden onchange="this.form.submit()"></label>
    </form>
    <form method="post" style="display:flex;gap:8px;margin:0;flex:1">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <input type="text" name="mkdir" placeholder="<?php echo L('new_folder'); ?>" required style="padding:8px 12px;border:1px solid var(--border);border-radius:6px;outline:none;font-size:14px;color:var(--text);background:var(--bg);min-width:120px;transition:0.2s"><button class="btn" type="submit"><?php echo L('create'); ?></button>
    </form>
</div>
<div class="table-wrap"><table>
    <thead><tr><th><?php echo L('name'); ?></th><th class="hide-m"><?php echo L('size'); ?></th><th class="hide-m"><?php echo L('modified'); ?></th><th style="text-align:right"><?php echo L('actions'); ?></th></tr></thead>
    <tbody>
    <?php foreach($list as $f): if($this->isProtected($f)) continue; 
        $p=$this->fsPath.'/'.$f; $d=is_dir($p); 
        $rp=ltrim(substr($p,strlen(STORAGE_PATH)),'/\\'); 
        $sh=isset($sharesMap[$rp])?$sharesMap[$rp]:''; 
        $link = $this->baseUri.rtrim($this->reqPath,'/').'/'.rawurlencode($f);
    ?>
    <tr>
        <td><a href="<?php echo $link; ?>" class="link" target="<?php echo $d?'_self':'_blank';?>"><?php echo $d?$i_folder:$i_file;echo htmlspecialchars($f);if($sh)echo '<span style="font-size:10px;color:var(--accent);background:rgba(132,204,22,0.1);border:1px solid rgba(132,204,22,0.2);padding:0 5px;border-radius:4px;font-weight:600">SHARED</span>';?></a></td>
        <td class="hide-m"><?php echo $d?'-':$this->fmt(filesize($p)); ?></td><td class="hide-m"><?php echo date('Y-m-d H:i',filemtime($p)); ?></td>
        <td><div class="act-grp">
            <?php if(!$d):?>
                <a href="<?php echo $link; ?>?download=1" class="act-btn" data-tooltip="<?php echo L('download');?>"><?php echo $i_dl;?></a>
                <button type="button" class="act-btn" onclick="share('<?php echo htmlspecialchars($f);?>','<?php echo $sh;?>')" data-tooltip="<?php echo L('share');?>"><?php echo $i_share;?></button>
            <?php endif;?>
            <button type="button" class="act-btn" onclick="pop('rename','<?php echo htmlspecialchars($f);?>')" data-tooltip="<?php echo L('rename');?>"><?php echo $i_edit;?></button>
            <button type="button" class="act-btn" onclick="pop('copy','<?php echo htmlspecialchars($f);?>')" data-tooltip="<?php echo L('copy');?>"><?php echo $i_copy;?></button>
            <button type="button" class="act-btn" onclick="pop('move','<?php echo htmlspecialchars($f);?>')" data-tooltip="<?php echo L('move');?>"><?php echo $i_move;?></button>
            <button type="button" class="act-btn del" onclick="pop('delete','<?php echo htmlspecialchars($f);?>')" data-tooltip="<?php echo L('delete');?>"><?php echo $i_del;?></button>
        </div></td>
    </tr>
    <?php endforeach; if(count($list)<=2):?><tr><td colspan="4" style="text-align:center;padding:60px 20px;color:#9ca3af;font-style:italic"><?php echo L('empty');?></td></tr><?php endif;?>
    </tbody>
</table></div>
<div class="footer">&copy; <?php echo date('Y'); ?> EasyWebDAV <a href="https://github.com/Andeasw/EasyWebDAV-PHP" target="_blank" class="gh-icon" aria-label="GitHub"><svg width="98" height="96" viewBox="0 0 98 96" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z" fill="currentColor"/></svg></a></div>
</div>
<div id="modal" class="modal"><div class="modal-box"><h3 id="m-t" style="margin-top:0;color:var(--text)"></h3><div id="m-c"></div><div style="margin-top:24px;text-align:right;display:flex;justify-content:flex-end;gap:10px"><button type="button" class="btn" onclick="document.getElementById('modal').style.display='none'"><?php echo L('cancel');?></button> <button type="button" class="btn btn-p" id="m-ok"><?php echo L('ok');?></button></div></div></div>
<script>
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
}
if (localStorage.getItem('darkMode') === 'true') document.body.classList.add('dark-mode');
const cur='<?php echo $this->reqPath==='/'?'':$this->reqPath;?>';
function pop(a,n){
    const m=document.getElementById('modal'),t=document.getElementById('m-t'),c=document.getElementById('m-c'),ok=document.getElementById('m-ok');
    m.style.display='flex'; t.innerText=a.charAt(0).toUpperCase()+a.slice(1);
    let h=''; if(a==='delete') h='<p style="color:var(--text)"><?php echo L('del_confirm');?> "<strong>'+n+'</strong>"?</p>';
    else if(a==='rename') h='<input id="inp" value="'+n+'" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:6px;outline:none;background:var(--bg);color:var(--text);box-sizing:border-box">';
    else h='<input id="inp" value="'+cur+'" placeholder="<?php echo L('target_path');?>" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:6px;outline:none;background:var(--bg);color:var(--text);box-sizing:border-box">';
    c.innerHTML=h;
    if(document.getElementById('inp')) setTimeout(()=>document.getElementById('inp').focus(),50);
    ok.onclick=()=>{
        const f=document.createElement('form');f.method='post';f.innerHTML='<input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input name="action" value="'+a+'"><input name="name" value="'+n+'">';
        if(document.getElementById('inp')) f.innerHTML+='<input name="'+(a==='rename'?'newname':'target')+'" value="'+document.getElementById('inp').value+'">';
        document.body.appendChild(f);f.submit();
    };
    if(a==='delete'){ ok.className='btn btn-d'; ok.innerText='<?php echo L('delete');?>'; } else { ok.className='btn btn-p'; ok.innerText='<?php echo L('ok');?>'; }
}
function share(n,t){
    const m=document.getElementById('modal'); m.style.display='flex'; document.getElementById('m-t').innerText='<?php echo L('share_title');?>';
    let h=''; const ok=document.getElementById('m-ok');
    if(t) {
        h='<div style="display:flex;gap:8px;margin-bottom:20px"><input id="s-lnk" value="<?php echo BASE_URL;?>?s='+t+'" style="flex:1;padding:8px;border:1px solid var(--border);border-radius:6px;outline:none;background:var(--hover);color:var(--text)" readonly>';
        h+='<button type="button" class="btn" onclick="cpLn()"><?php echo L('copy_link');?></button></div>';
        h+='<button type="button" class="btn btn-d" onclick="subShare(\'delete\',\''+n+'\',\''+t+'\')" style="width:100%"><?php echo L('del_share');?></button>';
    } else h='<button type="button" class="btn btn-p" onclick="subShare(\'create\',\''+n+'\')" style="width:100%"><?php echo L('create');?> <?php echo L('share_link');?></button>';
    document.getElementById('m-c').innerHTML=h; ok.style.display='none';
}
function cpLn(){const c=document.getElementById('s-lnk');c.select();document.execCommand('copy');alert('<?php echo L('copied');?>');}
function subShare(a,n,t){ const f=document.createElement('form');f.method='post';f.innerHTML='<input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>"><input name="share_action" value="'+a+'"><input name="name" value="'+n+'"><input name="token" value="'+t+'">';document.body.appendChild(f);f.submit(); }
window.onclick=e=>{if(e.target.className==='modal')e.target.style.display='none'};
</script></body></html>
<?php
    }
}
?>
