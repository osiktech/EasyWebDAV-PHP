<?php
/**
 * Ultimate WebDAV & File Manager (Secured Edition)
 * Ver: 3.1 | PHP 5.6 - 8.4 Compatible
 * Security Fixes: Path Traversal, CSRF, Stream I/O, Output Encoding
 */

// ============================================================================
// 1. 系统初始化与配置 (System Init)
// ============================================================================

// 尝试解除环境限制 (注意：upload_max_filesize 通常需要在 php.ini 中修改)
@ini_set('display_errors', 0);
@ini_set('log_errors', 1);
@ini_set('memory_limit', '-1');       // 尽可能使用最大内存
@set_time_limit(0);                   // 脚本永不超时
@ignore_user_abort(true);             // 客户端断开连接后继续后台传输
date_default_timezone_set('UTC');

// 核心常量
define('ROOT_DIR', __DIR__);
define('SCRIPT_NAME', basename($_SERVER['SCRIPT_NAME']));
define('STORAGE_NAME', 'storage');
define('STORAGE_PATH', ROOT_DIR . DIRECTORY_SEPARATOR . STORAGE_NAME);
define('AUTH_FILE', ROOT_DIR . DIRECTORY_SEPARATOR . '.htpasswd.php'); // 使用 .php 后缀防止被直接下载读取

// 系统隐藏文件 (禁止通过 WebDAV 操作这些文件)
define('HIDDEN_FILES', serialize([
    '.', '..', '.htaccess', '.htpasswd', '.htpasswd.php', SCRIPT_NAME, basename(__FILE__)
]));

// ============================================================================
// 2. 环境自检 (Auto-Correction)
// ============================================================================

// [A] 初始化存储目录
if (!file_exists(STORAGE_PATH)) {
    if (!mkdir(STORAGE_PATH, 0755, true)) {
        http_response_code(500); die("Critical Error: Cannot create storage directory.");
    }
}

// [B] 存储目录安全锁 (禁止 HTTP 直接访问存储目录下的脚本)
$storeHt = STORAGE_PATH . DIRECTORY_SEPARATOR . '.htaccess';
if (!file_exists($storeHt)) {
    @file_put_contents($storeHt, "RemoveHandler .php .phtml .php3\nDeny from all");
}

// [C] 根目录路由自动配置 (仅当文件不存在时写入，避免覆盖用户配置)
$rootHt = ROOT_DIR . DIRECTORY_SEPARATOR . '.htaccess';
if (!file_exists($rootHt)) {
    $rules = "DirectoryIndex " . SCRIPT_NAME . "\n" .
             "<IfModule mod_rewrite.c>\nRewriteEngine On\n" .
             "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n" .
             "RewriteCond %{REQUEST_FILENAME} !-f\n" .
             "RewriteCond %{REQUEST_FILENAME} !-d\n" .
             "RewriteRule ^(.*)$ " . SCRIPT_NAME . " [QSA,L]\n</IfModule>\n" .
             "Options -Indexes";
    @file_put_contents($rootHt, $rules);
}

// ============================================================================
// 3. 身份验证 (Authentication)
// ============================================================================

// [场景1] 首次初始化
if (!file_exists(AUTH_FILE)) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['init_u'], $_POST['init_p'])) {
        $u = trim($_POST['init_u']);
        $p = $_POST['init_p'];
        if (strlen($u) < 1 || strlen($p) < 1) die("Username/Password cannot be empty.");
        
        $hash = password_hash($p, PASSWORD_DEFAULT);
        // 使用 return array 格式，即便被解析也是安全的代码
        $conf = "<?php return " . var_export(['u' => $u, 'h' => $hash], true) . ";";
        
        if (file_put_contents(AUTH_FILE, $conf)) {
            header("Location: " . $_SERVER['REQUEST_URI']); exit;
        } else {
            die("Error: Cannot write config file. Check permissions.");
        }
    }
    echo_html_setup();
    exit;
}

// [场景2] 登录鉴权
$auth = include AUTH_FILE;
$u = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';
$p = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : '';

if ($u !== $auth['u'] || !password_verify($p, $auth['h'])) {
    header('WWW-Authenticate: Basic realm="WebDAV Storage"');
    http_response_code(401);
    die('Unauthorized Access');
}

// ============================================================================
// 4. 请求处理 (Handler)
// ============================================================================

$server = new DavHandler();

// 浏览器表单操作 (添加简单的 CSRF 检查)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_FILES['file_upload']) || isset($_POST['new_folder']))) {
    $server->checkCsrf(); 
    if (isset($_FILES['file_upload'])) $server->handleBrowserUpload();
    if (isset($_POST['new_folder'])) $server->handleBrowserMkdir();
    exit;
}

// WebDAV 核心处理
$server->serve();

// ============================================================================
// 5. 核心逻辑类 (Core Logic)
// ============================================================================

class DavHandler {
    private $baseUri;
    private $reqPath; // 请求的相对路径 (如 /folder/file.txt)
    private $fsPath;  // 文件系统绝对路径
    private $hidden;

    public function __construct() {
        $this->hidden = unserialize(HIDDEN_FILES);
        $this->parsePath();
    }

    /**
     * 安全路径解析 (核心安全修复)
     * 使用栈式解析，彻底杜绝 ../ 目录穿越
     */
    private function parsePath() {
        // 1. 计算 Base URI
        $uri = rawurldecode(explode('?', $_SERVER['REQUEST_URI'])[0]);
        $scriptDir = dirname($_SERVER['SCRIPT_NAME']);
        $scriptDir = ($scriptDir === '/' || $scriptDir === '\\') ? '' : str_replace('\\', '/', $scriptDir);
        
        $scriptBase = '/' . SCRIPT_NAME;
        
        // 判断是否是通过脚本文件名直接访问
        if (strpos($uri, $scriptDir . $scriptBase) === 0) {
            $this->baseUri = $scriptDir . $scriptBase;
            $rel = substr($uri, strlen($this->baseUri));
        } else {
            // 通过 Rewrite 访问
            $this->baseUri = $scriptDir; 
            if ($scriptDir && strpos($uri, $scriptDir) === 0) {
                $rel = substr($uri, strlen($scriptDir));
            } else {
                $rel = $uri;
            }
        }
        
        // 规范化 baseUri 确保以 / 结尾以便拼接，但在输出 XML 时需要注意
        $this->baseUri = rtrim($this->baseUri, '/') . '/';
        $this->reqPath = empty($rel) ? '/' : $rel;

        // 2. 物理路径解析
        $this->fsPath = $this->resolveFsPath($this->reqPath);
    }

    /**
     * 将相对路径解析为安全的绝对路径
     */
    private function resolveFsPath($relativePath) {
        $parts = explode('/', str_replace('\\', '/', $relativePath));
        $stack = [];
        foreach ($parts as $part) {
            if ($part === '' || $part === '.') continue;
            if ($part === '..') {
                if (!empty($stack)) array_pop($stack);
            } else {
                $stack[] = $part;
            }
        }
        return STORAGE_PATH . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $stack);
    }

    /**
     * CSRF 检查 (针对浏览器 POST)
     */
    public function checkCsrf() {
        if (!isset($_SERVER['HTTP_REFERER']) && !isset($_SERVER['HTTP_ORIGIN'])) return; // 非浏览器环境可能没有
        
        $host = $_SERVER['HTTP_HOST'];
        $ref = isset($_SERVER['HTTP_REFERER']) ? parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) : null;
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? parse_url($_SERVER['HTTP_ORIGIN'], PHP_URL_HOST) : null;

        // 简单的同源检测
        if (($ref && $ref !== $host) || ($origin && $origin !== $host)) {
            http_response_code(403); die("CSRF validation failed.");
        }
    }

    public function serve() {
        try {
            $m = $_SERVER['REQUEST_METHOD'];
            switch ($m) {
                case 'GET':      $this->doGet(); break;
                case 'PUT':      $this->doPut(); break;
                case 'PROPFIND': $this->doPropfind(); break;
                case 'OPTIONS':  $this->doOptions(); break;
                case 'DELETE':   $this->doDelete(); break;
                case 'MKCOL':    $this->doMkcol(); break;
                case 'COPY':     $this->doCopyMove(false); break;
                case 'MOVE':     $this->doCopyMove(true); break;
                case 'HEAD':     $this->doHead(); break;
                case 'LOCK':     $this->doLock(); break;
                case 'UNLOCK':   $this->doUnlock(); break;
                default:         http_response_code(405); break;
            }
        } catch (Exception $e) { http_response_code(500); }
    }

    // ------------------------------------------------------------------------
    // WebDAV Implementation
    // ------------------------------------------------------------------------

    private function doOptions() {
        header('DAV: 1, 2');
        header('Allow: OPTIONS, GET, HEAD, DELETE, PROPFIND, PUT, MKCOL, COPY, MOVE, LOCK, UNLOCK');
        header('MS-Author-Via: DAV');
        exit;
    }

    private function doGet() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }

        if (is_dir($this->fsPath)) {
            $this->sendHtml();
            exit;
        }

        if ($this->isHidden(basename($this->fsPath))) { http_response_code(404); exit; }

        $size = filesize($this->fsPath);
        header('Content-Type: ' . $this->mime($this->fsPath));
        header('Content-Length: ' . $size);
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s T', filemtime($this->fsPath)));
        header('ETag: "' . md5($this->fsPath . $size . filemtime($this->fsPath)) . '"');

        // 清除缓冲区，进行流式输出
        while (ob_get_level()) ob_end_clean();
        $fp = fopen($this->fsPath, 'rb');
        if ($fp) {
            fpassthru($fp);
            fclose($fp);
        }
        exit;
    }

    private function doPut() {
        if ($this->isHidden(basename($this->fsPath))) { http_response_code(403); exit; }

        $dir = dirname($this->fsPath);
        if (!is_dir($dir)) mkdir($dir, 0755, true);

        $in = fopen('php://input', 'rb');
        $out = fopen($this->fsPath, 'wb');
        
        if ($in && $out) {
            stream_copy_to_stream($in, $out);
            fclose($in); fclose($out);
            http_response_code(201);
        } else {
            http_response_code(500);
        }
    }

    private function doPropfind() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        
        $depth = isset($_SERVER['HTTP_DEPTH']) ? (int)$_SERVER['HTTP_DEPTH'] : 1;
        
        header('HTTP/1.1 207 Multi-Status');
        header('Content-Type: application/xml; charset="utf-8"');
        
        echo '<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">';
        
        $files = [];
        if (is_dir($this->fsPath)) {
            $files[] = $this->fsPath;
            if ($depth !== 0) {
                $raw = scandir($this->fsPath);
                foreach ($raw as $node) {
                    if ($this->isHidden($node)) continue;
                    $files[] = $this->fsPath . DIRECTORY_SEPARATOR . $node;
                }
            }
        } else {
            if (!$this->isHidden(basename($this->fsPath))) $files[] = $this->fsPath;
        }

        foreach ($files as $f) {
            // 计算用于 URL 的相对路径
            $rel = substr($f, strlen(STORAGE_PATH));
            if ($rel === false) $rel = '';
            
            // 修复 URL 编码：分别编码每个路径段，避免转义斜杠
            $parts = explode('/', str_replace('\\', '/', $rel));
            $encodedParts = array_map('rawurlencode', $parts);
            // 这里 baseUri 已经包含尾部斜杠，parts 第一个元素通常是空字符串(因为路径以/开头)，所以需要处理
            $hrefPath = implode('/', $encodedParts);
            $href = rtrim($this->baseUri, '/') . $hrefPath;

            $stat = stat($f);
            $name = basename($f);
            
            echo '<D:response>';
            echo '<D:href>' . $href . '</D:href>';
            echo '<D:propstat><D:prop>';
            echo '<D:displayname>' . htmlspecialchars($name) . '</D:displayname>';
            echo '<D:getlastmodified>' . gmdate('D, d M Y H:i:s T', $stat['mtime']) . '</D:getlastmodified>';
            echo '<D:creationdate>' . date('Y-m-d\TH:i:s\Z', $stat['ctime']) . '</D:creationdate>';
            
            if (is_dir($f)) {
                echo '<D:resourcetype><D:collection/></D:resourcetype>';
            } else {
                echo '<D:resourcetype/>';
                echo '<D:getcontentlength>' . sprintf('%u', $stat['size']) . '</D:getcontentlength>';
                echo '<D:getcontenttype>' . $this->mime($f) . '</D:getcontenttype>';
            }
            echo '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>';
            echo '</D:response>';
        }
        echo '</D:multistatus>';
    }

    private function doDelete() {
        if (!file_exists($this->fsPath)) { http_response_code(404); exit; }
        if ($this->fsPath == STORAGE_PATH) { http_response_code(403); exit; } // 根保护
        $this->rm($this->fsPath);
        http_response_code(204);
    }

    private function doMkcol() {
        if (file_exists($this->fsPath)) { http_response_code(405); exit; }
        mkdir($this->fsPath, 0755, true) ? http_response_code(201) : http_response_code(409);
    }

    private function doCopyMove($isMove) {
        $destHeader = isset($_SERVER['HTTP_DESTINATION']) ? $_SERVER['HTTP_DESTINATION'] : '';
        if (!$destHeader) { http_response_code(400); exit; }
        
        // 解析 Destination Header
        $u = parse_url($destHeader);
        $dPath = rawurldecode($u['path']);
        
        // 尝试剥离 BaseURI 以获取相对路径
        // 注意：BaseURI 可能包含主机名，也可能只是路径，这里做简单的路径匹配
        $scriptPath = $this->baseUri;
        // 如果 baseUri 包含了 http 前缀(理论上不应在类里硬编码)，这里只处理路径部分
        // 这里逻辑简化：假设请求的是同一服务器的路径
        
        // 简单剥离逻辑：找到脚本入口后的路径
        // 如果 dPath 是 /script.php/folder/file
        // baseUri 是 /script.php/
        // 则相对路径是 folder/file
        
        // 更稳健的方法：匹配 Script Name
        $scriptName = SCRIPT_NAME; 
        $pos = strpos($dPath, $scriptName);
        if ($pos !== false) {
            $relDest = substr($dPath, $pos + strlen($scriptName));
        } else {
            // 可能是 Rewrite 模式，直接基于目录匹配
            $dir = dirname($_SERVER['SCRIPT_NAME']);
            $dir = ($dir == '/' || $dir == '\\') ? '' : $dir;
            if ($dir && strpos($dPath, $dir) === 0) {
                $relDest = substr($dPath, strlen($dir));
            } else {
                $relDest = $dPath;
            }
        }
        
        $target = $this->resolveFsPath($relDest);

        // 安全检查
        if ($this->isHidden(basename($target))) { http_response_code(403); exit; }

        $over = isset($_SERVER['HTTP_OVERWRITE']) ? $_SERVER['HTTP_OVERWRITE'] : 'T';
        if (file_exists($target)) {
            if ($over === 'F') { http_response_code(412); exit; }
            $this->rm($target);
        }

        if ($isMove) {
            rename($this->fsPath, $target) ? http_response_code(201) : http_response_code(500);
        } else {
            $this->cp($this->fsPath, $target);
            http_response_code(201);
        }
    }

    private function doLock() {
        // 这是一个假的 Lock 实现，足以骗过 Office 和 Windows 客户端
        $t = 'urn:uuid:' . uniqid();
        header('Content-Type: application/xml; charset="utf-8"');
        header('Lock-Token: <' . $t . '>');
        echo '<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>Infinity</D:depth><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>'.$t.'</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>';
        exit;
    }
    private function doUnlock() { http_response_code(204); }
    private function doHead() { file_exists($this->fsPath) ? http_response_code(200) : http_response_code(404); }

    // ------------------------------------------------------------------------
    // Browser Interface
    // ------------------------------------------------------------------------

    public function handleBrowserUpload() {
        if (!is_dir($this->fsPath)) die("Invalid directory");
        $file = $_FILES['file_upload'];
        if ($file['error'] === UPLOAD_ERR_OK) {
            $name = basename($file['name']);
            // 仅保留对系统文件的保护，不限制扩展名
            if (!$this->isHidden($name)) {
                move_uploaded_file($file['tmp_name'], $this->fsPath . DIRECTORY_SEPARATOR . $name);
            }
        }
        header("Location: " . $_SERVER['REQUEST_URI']);
    }

    public function handleBrowserMkdir() {
        if (!is_dir($this->fsPath)) die("Invalid directory");
        $name = trim($_POST['new_folder']);
        // 过滤斜杠防止创建多级目录，保留基本字符
        $name = str_replace(['/', '\\'], '', $name);
        if ($name && !$this->isHidden($name)) {
            @mkdir($this->fsPath . DIRECTORY_SEPARATOR . $name);
        }
        header("Location: " . $_SERVER['REQUEST_URI']);
    }

    private function sendHtml() {
        if (headers_sent()) return;
        header('Content-Type: text/html; charset=utf-8');
        $list = scandir($this->fsPath);
        
        usort($list, function($a, $b) {
            $ad = is_dir($this->fsPath . '/' . $a);
            $bd = is_dir($this->fsPath . '/' . $b);
            if ($ad === $bd) return strcasecmp($a, $b);
            return $ad ? -1 : 1;
        });

        $breadcrumbs = [];
        $parts = array_filter(explode('/', $this->reqPath));
        $acc = '';
        foreach($parts as $p) {
            $acc .= '/' . $p;
            $breadcrumbs[] = ['n'=>$p, 'p'=>$acc];
        }
        ?>
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>WebDAV: <?php echo htmlspecialchars($this->reqPath); ?></title>
        <style>
            :root { --p: #007bff; --bg: #f8f9fa; }
            body { font-family: -apple-system, sans-serif; margin: 0; background: var(--bg); color: #333; }
            .head { background: #fff; padding: 15px 20px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; }
            .path a { text-decoration: none; color: #555; } .path a:hover { color: var(--p); }
            .main { max-width: 1000px; margin: 20px auto; background: #fff; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
            .tools { padding: 15px; border-bottom: 1px solid #eee; background: #fafafa; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
            .item { display: flex; align-items: center; padding: 12px; border-bottom: 1px solid #f1f1f1; }
            .item:hover { background: #fdfdfd; }
            .icon { font-size: 22px; width: 40px; text-align: center; }
            .name { flex: 1; text-decoration: none; color: #333; font-weight: 500; }
            .name:hover { color: var(--p); }
            .meta { font-size: 13px; color: #888; margin-left: 15px; min-width: 80px; text-align: right; }
            .btn { background: var(--p); color: #fff; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; font-size: 14px; display: inline-block; }
            .btn-f { background: #fff; border: 1px solid #ddd; color: #333; }
            form { display: flex; gap: 5px; margin: 0; }
            input[type=file] { display: none; }
        </style>
        </head><body>
        <div class="head">
            <div class="path">
                <a href="<?php echo rtrim(dirname($this->baseUri), '/'); ?>/">Root</a> / 
                <?php foreach($breadcrumbs as $b): ?>
                    <a href="<?php echo rawurlencode(ltrim($b['p'],'/')); ?>"><?php echo htmlspecialchars($b['n']); ?></a> /
                <?php endforeach; ?>
            </div>
            <div style="font-size:12px;color:#999">PHP WebDAV v3.1</div>
        </div>
        <div class="main">
            <div class="tools">
                <?php if ($this->reqPath !== '/' && $this->reqPath !== ''): ?>
                    <a href=".." class="btn btn-f">⬆ Parent</a>
                <?php endif; ?>
                
                <form method="post" enctype="multipart/form-data">
                    <label class="btn">
                        Upload File <input type="file" name="file_upload" onchange="this.form.submit()">
                    </label>
                </form>

                <form method="post">
                    <input type="text" name="new_folder" placeholder="New Folder Name" style="padding:7px;border:1px solid #ddd;border-radius:4px" required>
                    <button type="submit" class="btn btn-f">+</button>
                </form>
            </div>
            
            <div class="list">
                <?php foreach ($list as $f): 
                    if ($this->isHidden($f)) continue;
                    $full = $this->fsPath . DIRECTORY_SEPARATOR . $f;
                    $isDir = is_dir($full);
                    // 浏览器链接编码
                    $href = str_replace('%2F', '/', rawurlencode($f));
                    $icon = $isDir ? '📁' : '📄';
                    $size = $isDir ? '-' : $this->fmt(filesize($full));
                    $date = date('Y-m-d H:i', filemtime($full));
                ?>
                <div class="item">
                    <span class="icon"><?php echo $icon; ?></span>
                    <a href="<?php echo $href; ?>" class="name"><?php echo htmlspecialchars($f); ?></a>
                    <span class="meta"><?php echo $date; ?></span>
                    <span class="meta"><?php echo $size; ?></span>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        </body></html>
        <?php
    }

    // ------------------------------------------------------------------------
    // Utils
    // ------------------------------------------------------------------------

    private function isHidden($name) {
        return in_array($name, $this->hidden);
    }

    private function rm($p) {
        if (is_dir($p)) { 
            foreach(scandir($p) as $i) {
                if ($i !== '.' && $i !== '..') $this->rm($p . DIRECTORY_SEPARATOR . $i); 
            }
            return rmdir($p); 
        }
        return unlink($p);
    }
    
    private function cp($s, $d) {
        if (is_dir($s)) { 
            mkdir($d); 
            foreach(scandir($s) as $i) {
                if ($i !== '.' && $i !== '..') $this->cp($s . DIRECTORY_SEPARATOR . $i, $d . DIRECTORY_SEPARATOR . $i); 
            }
        } else {
            copy($s, $d);
        }
    }

    private function mime($f) {
        $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
        $mimes = [
            'txt'=>'text/plain','html'=>'text/html','php'=>'text/plain',
            'css'=>'text/css','js'=>'application/javascript','json'=>'application/json',
            'jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif',
            'svg'=>'image/svg+xml','mp4'=>'video/mp4','mp3'=>'audio/mpeg',
            'pdf'=>'application/pdf','zip'=>'application/zip','rar'=>'application/octet-stream',
            'xml'=>'application/xml'
        ];
        return isset($mimes[$ext]) ? $mimes[$ext] : 'application/octet-stream';
    }

    private function fmt($b) {
        $u=['B','KB','MB','GB']; $i=0; while($b>=1024&&$i<3){$b/=1024;$i++;} return round($b,2).' '.$u[$i];
    }
}

// 辅助函数：输出初始设置页面
function echo_html_setup() {
    ?>
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>System Init</title>
    <style>
        body{background:#f4f6f9;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;margin:0}
        .box{background:#fff;padding:40px;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,0.05);width:300px;text-align:center}
        h2{color:#333;margin-top:0}
        input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:5px;box-sizing:border-box}
        button{width:100%;padding:12px;background:#28a745;color:#fff;border:none;border-radius:5px;font-size:16px;cursor:pointer}
        button:hover{background:#218838}
        .note{font-size:12px;color:#666;margin-top:15px;line-height:1.4}
    </style></head><body>
    <div class="box">
        <h2>Secure Storage</h2>
        <form method="post">
            <input type="text" name="init_u" placeholder="Set Username" required>
            <input type="password" name="init_p" placeholder="Set Password" required>
            <button type="submit">Complete Setup</button>
        </form>
        <div class="note"><b>Note:</b> Credentials are stored in <code>.htpasswd.php</code> inside the script directory. Delete it to reset.</div>
    </div></body></html>
    <?php
}
