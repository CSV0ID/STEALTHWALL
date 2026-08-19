<?php
/**
 * STEALTHWALL — Drop-in PHP / WordPress / HTML Protection Script.
 * 
 * Usage:
 *   1. In php.ini or .user.ini:
 *      auto_prepend_file = "/path/to/stealthwall.php"
 *   OR
 *   2. At the top of index.php / wp-config.php:
 *      require_once __DIR__ . '/stealthwall.php';
 */

(function() {
    $client_ip = $_SERVER['HTTP_CF_CONNECTING_IP'] 
              ?? $_SERVER['HTTP_X_FORWARDED_FOR'] 
              ?? $_SERVER['REMOTE_ADDR'] 
              ?? '127.0.0.1';
    
    // Extract first IP in X-Forwarded-For chain
    if (strpos($client_ip, ',') !== false) {
        $parts = explode(',', $client_ip);
        $client_ip = trim($parts[0]);
    }

    // Connect to local StealthWall decision daemon (port 9377)
    $control_url = getenv('STEALTHWALL_DAEMON_URL') ?: 'http://127.0.0.1:9377/internal/decide';
    
    $payload = json_encode([
        'ip' => $client_ip,
        'path' => $_SERVER['REQUEST_URI'] ?? '/',
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'ts' => microtime(true)
    ]);

    $ch = curl_init($control_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_TIMEOUT_MS, 50); // Max 50ms latency impact

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response && $http_code === 200) {
        $decision = json_decode($response, true);
        if (isset($decision['action']) && in_array($decision['action'], ['temp_block', 'provisional_block', 'long_cooldown_block'])) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'Forbidden',
                'message' => 'Access denied by StealthWall intrusion prevention system.',
                'incident_ip' => $client_ip
            ]);
            exit;
        }
    }
})();
