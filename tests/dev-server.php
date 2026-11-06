<?php

declare(strict_types=1);

[$cert, $key, $rulesFile, $logFile, $portFile] = array_slice($argv, 1);
$context = stream_context_create([
    'ssl' => [
        'local_cert' => $cert,
        'local_pk' => $key,
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
        'security_level' => 0,
    ],
]);
$socket = stream_socket_server('ssl://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
if ($socket === false) {
    fwrite(STDERR, $errstr.PHP_EOL);
    exit(1);
}
$name = stream_socket_get_name($socket, false);
$port = (int) substr((string) $name, (int) strrpos((string) $name, ':') + 1);
file_put_contents($portFile, (string) $port);

while (true) {
    $conn = @stream_socket_accept($socket, 5);
    if ($conn === false) {
        continue;
    }
    stream_set_timeout($conn, 5);
    try {
        $request = read_request($conn);
        file_put_contents($logFile, json_encode($request, JSON_UNESCAPED_SLASHES)."\n", FILE_APPEND);
        $rules = json_decode((string) file_get_contents($rulesFile), true);
        $rule = match_rule(is_array($rules) ? $rules : [], $request);
        if (isset($rule['sleep'])) {
            usleep((int) ((float) $rule['sleep'] * 1_000_000));
        }
        write_response($conn, $rule);
    } catch (Throwable $error) {
        @fwrite($conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    @fclose($conn);
}

function read_request($conn): array
{
    $raw = '';
    while (!str_contains($raw, "\r\n\r\n")) {
        $chunk = fread($conn, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $raw .= $chunk;
    }
    [$head, $rest] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
    $lines = explode("\r\n", $head);
    $requestLine = (string) array_shift($lines);
    preg_match('/^(\S+)\s+(\S+)/', $requestLine, $match);
    $headers = [];
    foreach ($lines as $line) {
        if (!str_contains($line, ':')) {
            continue;
        }
        [$name, $value] = explode(':', $line, 2);
        $headers[$name] = trim($value);
    }
    $length = 0;
    foreach ($headers as $name => $value) {
        if (strcasecmp($name, 'Content-Length') === 0) {
            $length = (int) $value;
        }
    }
    $body = $rest;
    while (strlen($body) < $length) {
        $chunk = fread($conn, $length - strlen($body));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $body .= $chunk;
    }

    return [
        'method' => $match[1] ?? '',
        'target' => $match[2] ?? '',
        'headers' => $headers,
        'body' => substr($body, 0, $length),
    ];
}

function match_rule(array $spec, array $request): array
{
    foreach ($spec['rules'] ?? [] as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        if (isset($rule['contains']) && !str_contains($request['target'], (string) $rule['contains'])) {
            continue;
        }
        if (isset($rule['method']) && strcasecmp($request['method'], (string) $rule['method']) !== 0) {
            continue;
        }

        return $rule;
    }

    return ['status' => 500, 'json' => ['message' => 'unexpected '.$request['target']]];
}

function write_response($conn, array $rule): void
{
    $mode = (string) ($rule['mode'] ?? '');
    if ($mode === 'chunk') {
        fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
        $piece = str_repeat('A', 64 * 1024);
        $sent = 0;
        while ($sent < 9 * 1024 * 1024) {
            $payload = dechex(strlen($piece))."\r\n".$piece."\r\n";
            if (fwrite($conn, $payload) === false) {
                return;
            }
            $sent += strlen($piece);
        }

        return;
    }
    if ($mode === 'clen') {
        fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20000000\r\nConnection: close\r\n\r\n");

        return;
    }
    if ($mode === 'short') {
        $payload = '{"name":"envelopes/11111111-1111-4111-8111-111111111111"}';
        fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 80\r\nConnection: close\r\n\r\n".$payload);

        return;
    }
    if ($mode === 'close') {
        return;
    }
    if ($mode === 'redirect') {
        fwrite($conn, "HTTP/1.1 302 Found\r\nLocation: /secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        return;
    }
    $status = (int) ($rule['status'] ?? 200);
    $extra = '';
    foreach ($rule['headers'] ?? [] as $name => $value) {
        $extra .= $name.': '.$value."\r\n";
    }
    if (isset($rule['json'])) {
        $json = $rule['json'];
        if (($rule['sent_time'] ?? '') === 'now' && is_array($json)) {
            $json['sent_time'] = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s\Z');
        }
        $body = json_encode($json, JSON_UNESCAPED_SLASHES);
        $type = 'application/json';
    } else {
        $body = (string) ($rule['body'] ?? '');
        $type = (string) ($rule['content_type'] ?? 'text/plain');
    }
    if (!empty($rule['gzip'])) {
        $body = gzencode((string) $body);
        $extra .= "Content-Encoding: gzip\r\n";
    }
    $reason = $status === 412 ? 'Precondition Failed' : ($status === 302 ? 'Found' : 'OK');
    fwrite($conn, 'HTTP/1.1 '.$status.' '.$reason."\r\n".$extra.'Content-Type: '.$type."\r\nContent-Length: ".strlen((string) $body)."\r\nConnection: close\r\n\r\n".(string) $body);
}
