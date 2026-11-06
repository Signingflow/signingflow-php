<?php

declare(strict_types=1);

namespace Signingflow;

final class Config
{
    public const OFFICIAL_HOST = 'api.signingflow.com';

    public const DEFAULT_BASE_URL = 'https://api.signingflow.com';

    public string $apiKey;

    public string $workspaceId;

    public string $wireEnv;

    public string $baseUrl;

    public bool $allowCustomBaseUrl;

    public float $timeout;

    public int $retries;

    /** @var list<string> */
    public array $uploadHosts;

    public string $channel;

    public string $funnel;

    public string $uploadRoot;

    public string $caBundle;

    public function __construct(string $apiKey, array $options = [])
    {
        $this->apiKey = trim($apiKey);
        if ($this->apiKey === '') {
            throw new InvalidRequestError('API key is required.');
        }
        $this->workspaceId = trim((string) ($options['workspace_id'] ?? ''));
        if ($this->workspaceId === '') {
            throw new InvalidRequestError('workspace_id is required.');
        }
        $this->wireEnv = self::normalizeEnv($options['env'] ?? null);
        $base = trim((string) ($options['base_url'] ?? ''));
        if ($base === '') {
            $base = self::DEFAULT_BASE_URL;
        }
        $base = rtrim($base, '/');
        $parsed = parse_url($base);
        if (!is_array($parsed) || empty($parsed['scheme']) || empty($parsed['host'])) {
            throw new InvalidRequestError('base_url must be an absolute URL.');
        }
        if ($parsed['scheme'] !== 'https') {
            throw new InvalidRequestError('base_url must be https.');
        }
        if (isset($parsed['user']) || isset($parsed['pass'])) {
            throw new InvalidRequestError('base_url must not include a username or password.');
        }
        if (str_contains($base, "\0")) {
            throw new InvalidRequestError('base_url must be an absolute URL.');
        }
        $allow = (bool) ($options['allow_custom_base_url'] ?? false);
        if ($parsed['host'] !== self::OFFICIAL_HOST && !$allow) {
            throw new InvalidRequestError('base_url host must be api.signingflow.com, or set allow_custom_base_url.');
        }
        $this->baseUrl = $base;
        $this->allowCustomBaseUrl = $allow;
        $timeout = $options['timeout'] ?? 30;
        if (is_bool($timeout) || !is_int($timeout) && !is_float($timeout) || $timeout <= 0) {
            throw new InvalidRequestError('timeout must be positive.');
        }
        $this->timeout = (float) $timeout;
        $retries = $options['max_network_retries'] ?? 2;
        if (is_bool($retries) || !is_int($retries) || $retries < 0) {
            throw new InvalidRequestError('max_network_retries must be a whole number of zero or more.');
        }
        $this->retries = $retries;
        $this->uploadHosts = self::uploadHosts($options['upload_hosts'] ?? null);
        $this->channel = trim((string) ($options['channel'] ?? ''));
        $this->funnel = trim((string) ($options['funnel'] ?? ''));
        $this->uploadRoot = trim((string) ($options['upload_root'] ?? ''));
        $this->caBundle = trim((string) ($options['ca_bundle'] ?? ''));
        foreach ([$this->apiKey, $this->workspaceId, $this->channel, $this->funnel] as $value) {
            if (self::badHeader($value)) {
                throw new InvalidRequestError('invalid header value');
            }
        }
    }

    public static function badHeader(string $value): bool
    {
        return str_contains($value, "\r") || str_contains($value, "\n") || str_contains($value, "\0");
    }

    private static function normalizeEnv(mixed $env): string
    {
        if ($env === 'sandbox' || $env === 'SANDBOX') {
            return 'SANDBOX';
        }
        if ($env === 'live' || $env === 'LIVE') {
            return 'LIVE';
        }
        throw new InvalidRequestError('env must be sandbox or live.');
    }

    /** @return list<string> */
    private static function uploadHosts(mixed $hosts): array
    {
        if ($hosts === null) {
            $hosts = ['storage.googleapis.com'];
        }
        if (!is_array($hosts)) {
            throw new InvalidRequestError('Each upload_hosts entry must be a specific host, not a public suffix.');
        }
        $cleaned = [];
        foreach ($hosts as $host) {
            $host = strtolower(trim((string) $host));
            if ($host === '') {
                continue;
            }
            $dots = substr_count($host, '.');
            if ($dots < 2 || str_starts_with($host, '.') || str_ends_with($host, '.') || str_contains($host, '..')) {
                throw new InvalidRequestError('Each upload_hosts entry must be a specific host, not a public suffix.');
            }
            $cleaned[] = $host;
        }

        return $cleaned;
    }
}
