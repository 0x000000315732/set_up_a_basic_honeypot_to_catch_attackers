<?php

function get_ip_location($ip) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://ipinfo.io/{$ip}/json');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);

    $output = curl_exec($ch);

    if(curl_errno($no)) {
        return "Error: " . curl_error($ch);
    }

    curl_close($ch);
    return json_decode($output, true);
}

function is_vpn_free($ip) {
    // ProxyCheck.io offers 1,000 free queries per day without even needing a key
    // But it's better to sign up for a free key to track usage.
    $url = "https://proxycheck.io/v2/{$ip}?vpn=1";

    $json = file_get_contents($url);
    $data = json_decode($json, true);

    if(isset($data[$ip]['proxy']) && $data[$ip]['proxy'] === "yes") {
        return true;
    }
    return false;
}

function is_tor_exit_note($ip) {
    // Reverse the IP address (e.g., 1.2.3.4 becomes 4.3.2.1)
    $reverse_ip = implode('.', array_reverse(explode('.', $ip)));

    // The query format: [Reversed IP].[Port].[Target IP].ip-port.exitlist.torproject.org
    // We can simplify it just to check if the IP is an exit node at all:
    $query = $reverse_ip . ".dnsel.torproject.org";

    if(gethostbyname($query) === '127.0.0.2') {
        return true;
    }
    return false;
}

$fingerprint = [
    'time'              => date('Y-m-d H:i:s'),
    'ip'                => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    'user_agent'        => $_SERVER['HTTP_USER_AGENT'] ?? 'unkown',
    'accept_encoding'   => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'none',
    'accept_langauge'   => $_SERVER['HTTP_CONNECTION'] ?? 'none',
    'referer'           => $_SERVER['HTTP_REFERER'] ?? 'direct access',
    'query_string'      => $_SERVER['QUERY_STRING'] ?? '',
    'protocol'          => $_SERVER['SERVER_PROTOCOL'] ?? '',
];

$tor_status         = is_tor_exit_node($fingerprint['ip']);
$ip_location        = get_ip_location($fingerprint['ip']);
$ip_vpn             = is_vpn_free($fingerprint['ip']);

// Create a unique hash for this specific visitor profile
$fingerprint['request_hash'] = md5($fingerprint['ip'] . $fingerprint['user_agent']);

// Log to a file (ensure this directory is writable by the web server)
$log_entry = json_encode($fingerprint) . PHP_EOL;
file_put_contents(__DIR__ . '/trapped_bots.json', $log_entry, FILE_APPEND);