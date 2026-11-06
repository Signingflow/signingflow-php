<?php

declare(strict_types=1);

final class LocalServer
{
    public int $port = 0;

    public string $log = '';

    public string $err = '';

    public string $rulesFile = '';

    private $process = null;

    /** @param list<array<string, mixed>> $rules */
    public static function start(string $cert, string $key, array $rules): self
    {
        $server = new self();
        $server->rulesFile = tempnam(sys_get_temp_dir(), 'sf-rules-');
        $server->log = tempnam(sys_get_temp_dir(), 'sf-log-');
        $portFile = tempnam(sys_get_temp_dir(), 'sf-port-');
        file_put_contents($server->rulesFile, json_encode(['rules' => $rules], JSON_UNESCAPED_SLASHES));
        file_put_contents($server->log, '');
        $command = [
            PHP_BINARY,
            '-d', 'xdebug.mode=off',
            '-d', 'ffi.enable=true',
            __DIR__.'/dev-server.php',
            $cert,
            $key,
            $server->rulesFile,
            $server->log,
            $portFile,
        ];
        $server->err = $server->log.'.err';
        $server->process = proc_open($command, [1 => ['file', '/dev/null', 'a'], 2 => ['file', $server->err, 'a']], $pipes);
        $deadline = microtime(true) + 5;
        while (microtime(true) < $deadline) {
            $raw = trim((string) @file_get_contents($portFile));
            if ($raw !== '') {
                $server->port = (int) $raw;
                break;
            }
            usleep(20_000);
        }
        if ($server->port === 0) {
            $server->stop();
            throw new RuntimeException('The local test server did not start.');
        }

        return $server;
    }

    /** @param list<array<string, mixed>> $rules */
    public function rules(array $rules): void
    {
        file_put_contents($this->rulesFile, json_encode(['rules' => $rules], JSON_UNESCAPED_SLASHES));
    }

    /** @return list<array<string, mixed>> */
    public function seen(): array
    {
        $raw = (string) @file_get_contents($this->log);
        $rows = [];
        foreach (explode("\n", trim($raw)) as $line) {
            if ($line === '') {
                continue;
            }
            $decoded = json_decode($line, true);
            if (is_array($decoded)) {
                $rows[] = $decoded;
            }
        }

        return $rows;
    }

    public function header(array $headers, string $name): string
    {
        foreach ($headers as $key => $value) {
            if (strcasecmp((string) $key, $name) === 0) {
                return (string) $value;
            }
        }

        return '';
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
            $this->process = null;
        }
    }
}
