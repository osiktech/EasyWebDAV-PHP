<?php
/**
 * Ultimate Single File PHP WebDAV Server
 * Features: Auto-Config, Hidden System Files, Large File Support, Browser View
 */

// ============================================================================
// 1. 配置区域 (Configuration)
// ============================================================================

// 认证信息
define('DAV_USER', 'admin');
define('DAV_PASS', '123456');

// 存储文件夹名称 (脚本会自动创建，并将其作为根目录展示给用户)
define('STORAGE_NAME', 'data'); 

// ============================================================================
// 2. 环境自动初始化 (Auto-Initialization)
// ============================================================================

ini_set('display_errors', 0);
ini_set('memory_limit', '256M'); // 适当增加内存防止小文件处理溢出
date_default_timezone_set('UTC');

$baseDir = __DIR__;
$storageDir = $baseDir . DIRECTORY_SEPARATOR . STORAGE_NAME;

// [Auto-Setup 1] 创建存储目录
if (!file_exists($storageDir)) {
    if (!mkdir($storageDir, 0777, true)) {
        http_response_code(500); die("Error: Cannot create storage directory.");
    }
}

// [Auto-Setup 2] 生成根目录 .htaccess (路由与认证修复)
$rootHtaccess = $baseDir . '/.htaccess';
if (!file_exists($rootHtaccess)) {
    $rules = <<<EOF
DirectoryIndex index.php
<IfModule mod_rewrite.c>
RewriteEngine On
# 修复部分环境 Auth 头丢失
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
# 将所有非真实文件请求转发给 index.php
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]
</IfModule>
Options -Indexes
EOF;
    @file_put_contents($rootHtaccess, $rules);
}

// [Auto-Setup 3] 生成数据目录 .htaccess (禁止直接 HTTP 访问，必须走 PHP)
$dataHtaccess = $storageDir . '/.htaccess';
if (!file_exists($dataHtaccess)) {
    @file_put_contents($dataHtaccess, "Deny from all");
}

// 启动服务器
$server = new WebDAVServer($storageDir);
$server->serve();

/**
 * WebDAV 核心逻辑类
 */
class WebDAVServer {
    private $baseUri;    // Web 访问的基础路径 (用于 XML href)
    private $reqPath;    // 用户请求的相对路径 (例如 /photos/a.jpg)
    private $fsPath;     // 服务器上的物理路径 (例如 /var/www/data/photos/a.jpg)
    private $storageDir; // 数据根目录物理路径

    public function __construct($storageDir) {
        $this->storageDir = realpath($storageDir);
        $this->checkAuth();
        $this->parsePath();
    }

    /**
     * 智能路径解析：兼容根目录部署和子目录部署
     */
    private function parsePath() {
        $uri = rawurldecode(explode('?', $_SERVER['REQUEST_URI'])[0]);
        
        // 计算脚本所在的 Web 目录
        $scriptDir = dirname($_SERVER['SCRIPT_NAME']);
        // 统一分隔符为 /
        $scriptDir = ($scriptDir === '/' || $scriptDir === '\\') ? '' : str_replace('\\', '/', $scriptDir);
        
        $this->baseUri = $scriptDir;

        // 计算相对路径
        $rel = '/';
        if (strpos($uri, $scriptDir) === 0) {
            $rel = substr($uri, strlen($scriptDir));
        }
        
        // 如果客户端显式请求了 /index.php，将其剔除
        $scriptBase = '/' . basename($_SERVER['SCRIPT_NAME']);
        if (strpos($rel, $scriptBase) === 0) {
            $rel = substr($rel, strlen($scriptBase));
        }
        
        $this->reqPath = empty($rel) ? '/' : $rel;
        
        // 安全清洗：防止 ../ 目录遍历攻击
        $safePath = str_replace(array('../', '..\\'), '', $this->reqPath);
        $this->fsPath = $this->storageDir . $safePath;
    }

    public function serve() {
        try {
            $method = strtoupper($_SERVER['REQUEST_METHOD']);
            switch ($method) {
                case 'OPTIONS':  $this->doOptions(); break;
                case 'PROPFIND': $this->doPropfind(); break; // 列表
                case 'GET':      $this->doGet(); break;      // 下载/浏览
                case 'PUT':      $this->doPut(); break;      // 上传
                case 'DELETE':   $this->doDelete(); break;   // 删除
                case 'MKCOL':    $this->doMkcol(); break;    // 建文件夹
                case 'COPY':     $this->doCopyMove(false); break;
                case 'MOVE':     $this->doCopyMove(true); break;
                case 'HEAD':     $this->doHead(); break;
                case 'LOCK':     $this->doLock(); break;     // 伪锁
                case 'UNLOCK':   $this->doUnlock(); break;
                default:         http_response_code(405); break;
            }
        } catch (Exception $e) {
            http_response_code(500);
        }
    }

    // ========================================================================
    // 核心方法实现
    // ========================================================================

    private function doOptions() {
        header('DAV: 1, 2');
        header('Allow: OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, MKCOL, COPY, MOVE, LOCK, UNLOCK');
        header('MS-Author-Via: DAV');
        exit;
    }

    private function doPropfind() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }

        $depth = isset($_SERVER['HTTP_DEPTH']) ? (int)$_SERVER['HTTP_DEPTH'] : 1;
        
        header('HTTP/1.1 207 Multi-Status');
        header('Content-Type: application/xml; charset="utf-8"');
        
        echo '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';

        // 如果是文件，当作单条目列表处理
        // 如果是目录，根据 Depth 决定是否列出子项
        $files = [];
        if (is_dir($this->fsPath)) {
            $files[] = $this->fsPath; // 目录自身
            if ($depth !== 0) {
                $scanned = scandir($this->fsPath);
                foreach ($scanned as $node) {
                    if ($this->isHidden($node)) continue; // 关键：隐藏系统文件
                    $files[] = $this->fsPath . (substr($this->fsPath, -1) === '/' ? '' : '/') . $node;
                }
            }
        } else {
            $files[] = $this->fsPath;
        }

        foreach ($files as $file) {
            $this->emitXmlResponse($file);
        }
        
        echo '</D:multistatus>';
    }

    private function emitXmlResponse($file) {
        // 计算 Web href (BaseURI + Relative Path)
        // 1. 获取相对于 storageDir 的路径
        $relPath = substr($file, strlen($this->storageDir));
        if ($relPath === false) $relPath = '/'; // 根目录
        
        // 2. URL 编码 (保留斜杠)
        $href = $this->baseUri . str_replace('%2F', '/', rawurlencode($relPath));
        
        $stat = stat($file);
        $isDir = is_dir($file);

        echo '<D:response>';
        echo '<D:href>' . $href . '</D:href>';
        echo '<D:propstat><D:prop>';
        echo '<D:displayname>' . htmlspecialchars(basename($file)) . '</D:displayname>';
        // ISO 8601 creation date
        echo '<D:creationdate>' . date('Y-m-d\TH:i:s\Z', $stat['ctime']) . '</D:creationdate>';
        // RFC 1123 modified date
        echo '<D:getlastmodified>' . gmdate('D, d M Y H:i:s T', $stat['mtime']) . '</D:getlastmodified>';
        
        if ($isDir) {
            echo '<D:resourcetype><D:collection/></D:resourcetype>';
        } else {
            echo '<D:resourcetype/>';
            echo '<D:getcontentlength>' . $stat['size'] . '</D:getcontentlength>';
            echo '<D:getcontenttype>' . $this->getMimeType($file) . '</D:getcontenttype>';
        }
        
        echo '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>';
        echo '</D:response>';
    }

    private function doGet() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }

        // 1. 如果是目录 -> 返回 HTML 页面 (浏览器查看)
        if (is_dir($this->fsPath)) {
            $this->sendHtmlDirectory();
            exit;
        }

        // 2. 如果是文件 -> 下载/预览
        $size = filesize($this->fsPath);
        header('Content-Type: ' . $this->getMimeType($this->fsPath));
        header('Content-Length: ' . $size);
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s T', filemtime($this->fsPath)));
        header('ETag: "' . md5($this->fsPath . $size) . '"'); // 简单的 ETag

        $fp = fopen($this->fsPath, 'rb');
        fpassthru($fp); // 使用流输出，支持大文件
        exit;
    }

    private function doPut() {
        // 确保父目录存在
        $dir = dirname($this->fsPath);
        if (!is_dir($dir)) { http_response_code(409); exit; } // Conflict

        $in = fopen('php://input', 'r');
        $out = fopen($this->fsPath, 'w');
        
        if ($in && $out) {
            stream_copy_to_stream($in, $out);
            fclose($in);
            fclose($out);
            http_response_code(201); // Created
        } else {
            http_response_code(500);
        }
    }

    private function doDelete() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        if ($this->rmRecursive($this->fsPath)) http_response_code(204);
        else http_response_code(500);
    }

    private function doMkcol() {
        if (file_exists($this->fsPath)) { http_response_code(405); exit; } // Allow header needed technically, but 405 is fine
        if (mkdir($this->fsPath)) http_response_code(201);
        else http_response_code(409); // Parent likely missing
    }

    private function doCopyMove($isMove) {
        $destHeader = isset($_SERVER['HTTP_DESTINATION']) ? $_SERVER['HTTP_DESTINATION'] : '';
        if (!$destHeader) { http_response_code(400); exit; }

        // 解析 Destination Path
        $url = parse_url($destHeader);
        $destPath = rawurldecode($url['path']);
        
        // 移除 BaseURI
        if ($this->baseUri !== '/' && strpos($destPath, $this->baseUri) === 0) {
            $destPath = substr($destPath, strlen($this->baseUri));
        }

        $targetFs = $this->storageDir . $destPath; // 目标物理路径

        // 检查覆盖 (WebDAV 默认 Overwrite: T)
        $overwrite = isset($_SERVER['HTTP_OVERWRITE']) ? $_SERVER['HTTP_OVERWRITE'] : 'T';
        if (file_exists($targetFs)) {
            if (strtoupper($overwrite) === 'F') { http_response_code(412); exit; }
            $this->rmRecursive($targetFs);
        }

        // 检查源
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }

        $result = false;
        if ($isMove) {
            $result = rename($this->fsPath, $targetFs);
        } else {
            $result = $this->copyRecursive($this->fsPath, $targetFs);
        }

        http_response_code($result ? (file_exists($targetFs) ? 201 : 204) : 500);
    }

    // ========================================================================
    // 辅助功能 & HTML 视图
    // ========================================================================

    private function sendHtmlDirectory() {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '<title>Index of ' . htmlspecialchars($this->reqPath) . '</title>';
        echo '<style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 20px; color: #333; }
            h2 { border-bottom: 1px solid #eee; padding-bottom: 10px; }
            ul { list-style: none; padding: 0; }
            li { padding: 8px 0; border-bottom: 1px solid #f4f4f4; display: flex; align-items: center; }
            a { text-decoration: none; color: #0066cc; font-size: 16px; margin-left: 10px; }
            a:hover { text-decoration: underline; }
            .icon { font-size: 20px; width: 30px; text-align: center; }
            .size { margin-left: auto; color: #888; font-size: 14px; font-family: monospace; }
        </style></head><body>';
        
        echo '<h2>Index of ' . htmlspecialchars($this->reqPath) . '</h2><ul>';

        // 上级目录链接
        if ($this->reqPath !== '/') {
            echo '<li><span class="icon">📂</span><a href="..">Parent Directory</a></li>';
        }

        $files = scandir($this->fsPath);
        
        // 排序：文件夹在前，文件在后
        usort($files, function($a, $b) {
            if ($this->isHidden($a)) return 0; // 忽略
            $aDir = is_dir($this->fsPath . '/' . $a);
            $bDir = is_dir($this->fsPath . '/' . $b);
            if ($aDir === $bDir) return strcasecmp($a, $b);
            return $aDir ? -1 : 1;
        });

        foreach ($files as $file) {
            if ($this->isHidden($file)) continue;

            $fullPath = $this->fsPath . '/' . $file;
            $isDir = is_dir($fullPath);
            $icon = $isDir ? '📂' : '📄';
            $name = htmlspecialchars($file);
            $href = rawurlencode($file); // 浏览器友好链接
            $size = $isDir ? '-' : $this->formatSize(filesize($fullPath));

            echo "<li><span class='icon'>$icon</span><a href='$href'>$name</a><span class='size'>$size</span></li>";
        }
        
        echo '</ul></body></html>';
    }

    // 隐藏系统文件逻辑
    private function isHidden($file) {
        return ($file === '.' || $file === '..' || $file === '.htaccess' || substr($file, 0, 1) === '.');
    }

    // 格式化文件大小
    private function formatSize($bytes) {
        if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
        if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
        if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
        return $bytes . ' B';
    }

    private function getMimeType($file) {
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $mimes = [
            'txt'=>'text/plain', 'html'=>'text/html', 'css'=>'text/css', 'js'=>'application/javascript', 'json'=>'application/json',
            'jpg'=>'image/jpeg', 'jpeg'=>'image/jpeg', 'png'=>'image/png', 'gif'=>'image/gif', 'svg'=>'image/svg+xml',
            'mp3'=>'audio/mpeg', 'wav'=>'audio/wav', 'mp4'=>'video/mp4', 'webm'=>'video/webm',
            'pdf'=>'application/pdf', 'zip'=>'application/zip', 'rar'=>'application/x-rar-compressed'
        ];
        return isset($mimes[$ext]) ? $mimes[$ext] : 'application/octet-stream';
    }

    private function checkAuth() {
        if (!isset($_SERVER['PHP_AUTH_USER']) || 
            $_SERVER['PHP_AUTH_USER'] !== DAV_USER || 
            $_SERVER['PHP_AUTH_PW'] !== DAV_PASS) {
            header('WWW-Authenticate: Basic realm="WebDAV"');
            http_response_code(401);
            die('Unauthorized');
        }
    }

    // WebDAV 锁机制 (欺骗 Windows 客户端)
    private function doLock() {
        $token = 'urn:uuid:' . uniqid();
        header('Content-Type: application/xml; charset="utf-8"');
        header('Lock-Token: <' . $token . '>');
        echo '<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>Infinity</D:depth><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>'.$token.'</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>';
        exit;
    }
    private function doUnlock() { http_response_code(204); exit; }
    private function doHead() { file_exists($this->fsPath) ? http_response_code(200) : http_response_code(404); exit; }

    private function rmRecursive($p) {
        if (!is_dir($p)) return unlink($p);
        foreach (scandir($p) as $i) if ($i!='.' && $i!='..') $this->rmRecursive($p.DIRECTORY_SEPARATOR.$i);
        return rmdir($p);
    }
    private function copyRecursive($s, $d) {
        if (is_dir($s)) {
            if (!is_dir($d)) mkdir($d);
            foreach (scandir($s) as $f) if ($f!='.' && $f!='..') $this->copyRecursive($s.'/'.$f, $d.'/'.$f);
            return true;
        } return copy($s, $d);
    }
}