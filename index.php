<?php
/**
 * MilesWeb / Shared Hosting Reverse Proxy Bridge to FastAPI Uvicorn
 * Forwards all incoming HTTP requests to http://127.0.0.1:8000
 */

// Enable CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH");
header("Access-Control-Allow-Headers: Authorization, Content-Type, Accept, Origin, X-Requested-With");

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$backend_host = 'http://127.0.0.1:8000';
$request_uri = $_SERVER['REQUEST_URI'] ?? '/';
// Strip /index.php prefix if passed by rewrite engine
$request_uri = preg_replace('#^/index\.php#i', '', $request_uri);
if (empty($request_uri)) {
    $request_uri = '/';
}
$target_url = $backend_host . $request_uri;

$ch = curl_init($target_url);

$method = $_SERVER['REQUEST_METHOD'];
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

// Forward request body
$input = file_get_contents('php://input');
if (!empty($input) || in_array($method, ['POST', 'PUT', 'PATCH'])) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
}

// Forward incoming request headers
$headers = [];
$incoming_headers = function_exists('getallheaders') ? getallheaders() : [];
foreach ($incoming_headers as $key => $value) {
    $lower = strtolower($key);
    if (!in_array($lower, ['host', 'content-length'])) {
        $headers[] = "$key: $value";
    }
}
if (!empty($input)) {
    $headers[] = 'Content-Length: ' . strlen($input);
}
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
curl_setopt($ch, CURLOPT_TIMEOUT, 60);

$response = curl_exec($ch);

if ($response === false) {
    http_response_code(502);
    header('Content-Type: application/json');
    echo json_encode([
        "error" => "FastAPI backend is unreachable on port 8000.",
        "curl_error" => curl_error($ch),
        "hint" => "Make sure uvicorn is running: uvicorn app:app --host 127.0.0.1 --port 8000"
    ]);
    exit;
}

$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$res_headers = substr($response, 0, $header_size);
$res_body = substr($response, $header_size);
curl_close($ch);

http_response_code($status_code);

// Forward response headers
$header_lines = explode("\r\n", $res_headers);
foreach ($header_lines as $line) {
    if (strpos($line, ':') !== false) {
        $h_name = strtolower(trim(substr($line, 0, strpos($line, ':'))));
        if (!in_array($h_name, ['transfer-encoding', 'connection', 'access-control-allow-origin'])) {
            header($line, false);
        }
    }
}

echo $res_body;
