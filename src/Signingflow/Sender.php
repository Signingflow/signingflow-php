<?php

declare(strict_types=1);

namespace Signingflow;

final class Sender
{
    public const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

    private const UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    public function __construct(public Config $config)
    {
    }

    public function call(string $operationId, array $pathParams = [], array $query = [], ?array $body = null, string $idempotencyKey = ''): array
    {
        $spec = Allowlist::operation($operationId);
        $key = '';
        $payload = null;
        if (($spec['http'] ?? '') !== 'GET') {
            $payload = $body ?? [];
        }
        if (!empty($spec['idempotent'])) {
            $key = self::keyFor($idempotencyKey, $body);
            $payload['idempotencyKey'] = $key;
        }
        try {
            $path = Path::fill((string) $spec['path'], $pathParams);
            $url = Path::resolve($this->config->baseUrl, $path, $query);
        } catch (InvalidRequestError $error) {
            $error->idempotencyKey = $key;
            throw $error;
        }
        $rawQuery = (string) (parse_url($url, PHP_URL_QUERY) ?: '');
        if (Path::containsSecret($rawQuery, $this->config->apiKey)) {
            throw new InvalidRequestError('The API key must not be sent in the query string.', idempotencyKey: $key);
        }
        $retries = (($spec['http'] ?? '') === 'GET' || !empty($spec['idempotent'])) ? $this->config->retries : 0;
        $encoded = null;
        if ($payload !== null) {
            try {
                $encoded = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            } catch (\JsonException $error) {
                throw new InvalidRequestError('invalid request body');
            }
        }
        $attempt = 0;
        while (true) {
            try {
                [$status, $headers, $data] = $this->exchange((string) $spec['http'], $url, $encoded, $this->headers((string) $spec['http']));
            } catch (Error $error) {
                throw $error;
            } catch (\Throwable $error) {
                if ($attempt < $retries) {
                    $attempt++;
                    continue;
                }
                throw self::connectionError($error, $key);
            }
            if ($status >= 200 && $status < 300) {
                return self::parseSuccess($status, $headers['content-type'] ?? '', $data);
            }
            if ($attempt < $retries && self::retryable($status)) {
                $attempt++;
                Clock::sleep(Path::retryDelay(
                    $headers['rate-limit-retry-after'] ?? '',
                    $headers['rate-limit-reset-after'] ?? '',
                    Clock::now(),
                ));
                continue;
            }
            throw self::failure($status, $headers, $data, (string) ($spec['capability'] ?? ''), $key, $this->config->apiKey);
        }
    }

    public function putBytes(string $url, string $contentType, string $data): void
    {
        if (Config::badHeader($contentType)) {
            throw new InvalidRequestError('invalid header value');
        }
        $retries = $this->config->retries;
        $attempt = 0;
        $headers = [
            'Content-Type' => $contentType,
            'x-goog-if-generation-match' => '0',
        ];
        while (true) {
            try {
                [$status] = $this->exchange('PUT', $url, $data, $headers);
            } catch (Error $error) {
                throw $error;
            } catch (\Throwable $error) {
                if ($attempt < $retries) {
                    $attempt++;
                    continue;
                }
                throw new ConnectionError('The upload could not be reached.', statusCode: 0);
            }
            if (($status >= 200 && $status < 300) || $status === 412) {
                return;
            }
            if ($attempt < $retries && $status >= 500) {
                $attempt++;
                continue;
            }
            throw new APIError('Uploading the file to storage failed.', statusCode: $status);
        }
    }

    /** @return array<string, string> */
    public function headers(string $method): array
    {
        $header = [
            'Authorization' => 'Bearer '.$this->config->apiKey,
            'X-Request-Workspace-Id' => $this->config->workspaceId,
            'X-Request-Env' => $this->config->wireEnv,
            'X-Request-Source' => Version::SOURCE,
            'Accept' => 'application/json',
            'User-Agent' => Version::SOURCE,
        ];
        if ($this->config->channel !== '') {
            $header['X-Request-Channel'] = $this->config->channel;
        }
        if ($this->config->funnel !== '') {
            $header['X-Request-Funnel'] = $this->config->funnel;
        }
        if ($method !== 'GET') {
            $header['Content-Type'] = 'application/json';
        }

        return $header;
    }

    /** @param array<string, string> $headers
     * @return array{0: int, 1: array<string, string>, 2: string}
     */
    public function exchange(string $method, string $url, ?string $body, array $headers): array
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
            throw new InvalidRequestError('url must be https');
        }
        $headers['Accept-Encoding'] = 'identity';
        $headers['Expect'] = '';
        foreach ($headers as $value) {
            if (Config::badHeader((string) $value)) {
                throw new InvalidRequestError('invalid header value');
            }
        }
        $path = ($parts['path'] ?? '') !== '' ? $parts['path'] : '/';
        if (!empty($parts['query'])) {
            $path .= '?'.$parts['query'];
        }
        $curlUrl = 'https://'.$parts['host'];
        if (isset($parts['port'])) {
            $curlUrl .= ':'.$parts['port'];
        }
        $curlUrl .= $path;
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name.': '.$value;
        }
        $captured = '';
        $total = 0;
        $tooBig = false;
        $responseHeaders = [];
        $handle = curl_init();
        $options = [
            CURLOPT_URL => $curlUrl,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => (int) round($this->config->timeout * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int) round($this->config->timeout * 1000),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
            CURLOPT_PROXY => '',
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders, &$tooBig): int {
                $trim = trim($line);
                if ($trim === '' || str_starts_with($trim, 'HTTP/')) {
                    return strlen($line);
                }
                $split = explode(':', $trim, 2);
                if (count($split) === 2) {
                    $name = strtolower(trim($split[0]));
                    $value = trim($split[1]);
                    $responseHeaders[$name] = $value;
                    if ($name === 'content-length' && is_numeric($value) && (int) $value > self::MAX_RESPONSE_BYTES) {
                        $tooBig = true;

                        return 0;
                    }
                }

                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$captured, &$total, &$tooBig): int {
                $total += strlen($chunk);
                if ($total > self::MAX_RESPONSE_BYTES) {
                    $tooBig = true;

                    return 0;
                }
                $captured .= $chunk;

                return strlen($chunk);
            },
        ];
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            $options[CURLOPT_PROTOCOLS_STR] = 'https';
            $options[CURLOPT_REDIR_PROTOCOLS_STR] = 'https';
        } elseif (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTPS')) {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
            $options[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTPS;
        }
        if ($body !== null) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }
        if ($this->config->caBundle !== '') {
            $options[CURLOPT_CAINFO] = $this->config->caBundle;
        }
        curl_setopt_array($handle, $options);
        $ok = curl_exec($handle);
        $errno = curl_errno($handle);
        $error = curl_error($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        unset($handle);
        if ($tooBig) {
            throw new APIError('The API response is larger than 8 MB.', statusCode: $status);
        }
        if ($ok === false) {
            $emptyReply = defined('CURLE_GOT_NOTHING') ? CURLE_GOT_NOTHING : 52;
            if ($status >= 100 && $status < 200 && $errno === $emptyReply) {
                return [$status, $responseHeaders, $captured];
            }
            throw new \RuntimeException($error === '' ? 'curl failed' : $error, $errno);
        }
        if (self::bodyEndedEarly($responseHeaders, $captured)) {
            throw new APIError('The API response ended before the declared length.', statusCode: $status);
        }

        return [$status, $responseHeaders, $captured];
    }

    /** @param array<string, string> $headers */
    private static function bodyEndedEarly(array $headers, string $body): bool
    {
        $raw = $headers['content-length'] ?? '';
        if ($raw === '' || preg_match('/^\d+$/', $raw) !== 1) {
            return false;
        }

        return strlen($body) < (int) $raw;
    }

    public static function keyFor(string $supplied, ?array $body): string
    {
        $raw = trim($supplied);
        if ($raw === '' && is_array($body) && isset($body['idempotencyKey']) && is_string($body['idempotencyKey'])) {
            $raw = trim($body['idempotencyKey']);
        }
        if ($raw === '') {
            return self::uuid4();
        }
        if (preg_match(self::UUID, $raw) !== 1) {
            throw new InvalidRequestError('idempotencyKey must be a UUID.');
        }

        return $raw;
    }

    public static function uuid4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);

        return substr($hex, 0, 8).'-'.substr($hex, 8, 4).'-'.substr($hex, 12, 4).'-'.substr($hex, 16, 4).'-'.substr($hex, 20, 12);
    }

    /** @param array<string, string> $headers */
    private static function failure(int $status, array $headers, string $body, string $capability, string $key, string $apiKey): Error
    {
        $parsed = $body;
        if (trim($body) !== '') {
            try {
                $parsed = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                $parsed = $body;
            }
        }
        $message = Status::serverMessage($parsed);
        if ($message === '') {
            $message = trim($body) === '' ? 'Request failed with status '.$status.'.' : $body;
        }
        $fields = [
            'statusCode' => $status,
            'grpcCode' => Status::grpcCode($parsed),
            'traceCode' => Status::traceCode($parsed),
            'requestId' => $headers['x-request-id'] ?? '',
            'idempotencyKey' => $key,
            'capability' => $capability,
            'fieldViolations' => Redact::violations(Status::fieldViolations($parsed), $apiKey),
            'retryAfter' => ($headers['rate-limit-retry-after'] ?? '') !== ''
                ? $headers['rate-limit-retry-after']
                : ($headers['rate-limit-reset-after'] ?? ''),
        ];
        $message = Redact::message($message, $apiKey);
        if ($status === 401) {
            return new AuthenticationError($message, ...$fields);
        }
        if ($status === 403) {
            return new PermissionError($message, ...$fields);
        }
        if ($status === 409 && Status::mentionsIdempotency($parsed)) {
            $fields['resourceName'] = Status::resourceName($parsed);

            return new IdempotencyError($message, ...$fields);
        }
        if ($status === 429) {
            return new RateLimitError($message, ...$fields);
        }
        if ($status >= 400 && $status < 500) {
            return new InvalidRequestError($message, ...$fields);
        }

        return new APIError($message, ...$fields);
    }

    private static function parseSuccess(int $status, string $contentType, string $body): array
    {
        if (trim($body) === '') {
            return [];
        }
        if ($contentType !== '' && !str_contains($contentType, 'json') && !str_contains($contentType, 'text/')) {
            throw new APIError('The API returned a non-JSON body.', statusCode: $status);
        }
        try {
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new APIError('The API returned invalid JSON.', statusCode: $status);
        }
        if (!is_array($decoded)) {
            throw new APIError('The API returned invalid JSON.', statusCode: $status);
        }

        return $decoded;
    }

    private static function retryable(int $status): bool
    {
        return $status === 408 || $status === 429 || $status >= 500;
    }

    private static function connectionError(\Throwable $error, string $key): ConnectionError
    {
        $text = strtolower($error->getMessage());
        $timedOut = $error->getCode() === 28 || str_contains($text, 'timed out') || str_contains($text, 'timeout');
        if ($timedOut) {
            return new ConnectionError('The API timed out.', statusCode: 408, idempotencyKey: $key);
        }

        return new ConnectionError('The API could not be reached.', statusCode: 0, idempotencyKey: $key);
    }
}
