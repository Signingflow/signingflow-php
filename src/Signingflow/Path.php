<?php

declare(strict_types=1);

namespace Signingflow;

final class Path
{
    private const SEGMENT = '/^[A-Za-z0-9_-]+$/';

    public static function fill(string $template, ?array $params): string
    {
        $params = $params ?? [];
        $failure = null;
        $filled = preg_replace_callback('/\{([^}]+)\}/', static function (array $match) use ($params, &$failure): string {
            if ($failure !== null) {
                return '';
            }
            $token = $match[1];
            $name = explode('=', $token, 2)[0];
            $short = str_contains($name, '.') ? substr($name, strrpos($name, '.') + 1) : $name;
            $value = (string) ($params[$name] ?? $params[$short] ?? '');
            if ($value === '' && ($short === 'name' || str_starts_with($short, 'name_'))) {
                $value = (string) ($params['name'] ?? '');
            }
            if ($value === '') {
                $failure = new InvalidRequestError('missing path param '.$short);

                return '';
            }
            $escaped = [];
            foreach (explode('/', $value) as $part) {
                if (preg_match(self::SEGMENT, $part) !== 1) {
                    $failure = new InvalidRequestError('invalid path param '.$short);

                    return '';
                }
                $escaped[] = rawurlencode($part);
            }

            return implode('/', $escaped);
        }, $template);
        if ($failure !== null) {
            throw $failure;
        }

        return $filled ?? $template;
    }

    public static function resolve(string $baseUrl, string $path, ?array $query): string
    {
        $base = parse_url($baseUrl);
        if (!is_array($base) || empty($base['scheme']) || empty($base['host'])) {
            throw new InvalidRequestError('invalid path');
        }
        if (!str_starts_with($path, '/')) {
            throw new InvalidRequestError('invalid path');
        }
        $origin = $base['scheme'].'://'.$base['host'];
        if (isset($base['port'])) {
            $origin .= ':'.$base['port'];
        }
        $full = $origin.$path;
        $parts = parse_url($full);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== $base['scheme'] || ($parts['host'] ?? '') !== $base['host']) {
            throw new InvalidRequestError('invalid path');
        }
        if (($parts['port'] ?? null) !== ($base['port'] ?? null)) {
            throw new InvalidRequestError('invalid path');
        }
        $pairs = [];
        foreach ($query ?? [] as $key => $value) {
            if ($value) {
                $pairs[] = [(string) $key, (string) $value];
            }
        }
        $rawQuery = self::encode($pairs);
        $url = $origin.($parts['path'] ?? '/');
        if ($rawQuery !== '') {
            $url .= '?'.$rawQuery;
        }

        return $url;
    }

    /** @param list<array{0: string, 1: string}> $pairs */
    public static function encode(array $pairs): string
    {
        $out = [];
        foreach ($pairs as [$key, $value]) {
            $out[] = rawurlencode($key).'='.rawurlencode($value);
        }

        return implode('&', $out);
    }

    public static function containsSecret(string $rawQuery, string $secret): bool
    {
        if ($secret === '' || $rawQuery === '') {
            return false;
        }
        if (str_contains($rawQuery, $secret) || str_contains($rawQuery, rawurlencode($secret)) || str_contains($rawQuery, urlencode($secret))) {
            return true;
        }
        if (self::badPercent($rawQuery)) {
            return true;
        }
        foreach (explode('&', $rawQuery) as $part) {
            $eq = strpos($part, '=');
            $value = $eq === false ? $part : substr($part, $eq + 1);
            if (str_contains(rawurldecode($value), $secret) || str_contains(urldecode($value), $secret)) {
                return true;
            }
        }

        return false;
    }

    public static function allowedUploadUrl(string $raw, array $hosts): string
    {
        $parsed = parse_url($raw);
        if (!is_array($parsed) || empty($parsed['scheme']) || empty($parsed['host'])) {
            throw new InvalidRequestError('upload url rejected');
        }
        if ($parsed['scheme'] !== 'https') {
            throw new InvalidRequestError('upload url must be https');
        }
        if (isset($parsed['user']) || isset($parsed['pass'])) {
            throw new InvalidRequestError('upload url rejected');
        }
        if (str_contains($raw, "\0") || str_ends_with($parsed['host'], '.')) {
            throw new InvalidRequestError('upload url rejected');
        }
        $host = strtolower($parsed['host']);
        foreach ($hosts as $item) {
            if ($host === $item || str_ends_with($host, '.'.$item)) {
                return $raw;
            }
        }
        throw new InvalidRequestError('upload host rejected');
    }

    public static function retryDelay(string $retryAfter, string $resetAfter, \DateTimeImmutable $now): float
    {
        $when = self::parseRetry($retryAfter) ?? self::parseRetry($resetAfter);
        if ($when === null) {
            return 0.0;
        }
        $delay = $when->getTimestamp() - $now->getTimestamp();
        if ($delay < 0) {
            return 0.0;
        }
        if ($delay > 60) {
            return 60.0;
        }

        return (float) $delay;
    }

    public static function parseRetry(string $value): ?\DateTimeImmutable
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        if (str_ends_with($value, 'Z')) {
            $value = substr($value, 0, -1).'+00:00';
        }
        try {
            if (preg_match('/(?:Z|[+-]\d{2}:?\d{2})$/', $value) === 1) {
                return new \DateTimeImmutable($value);
            }

            return new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return null;
        }
    }

    private static function badPercent(string $raw): bool
    {
        $length = strlen($raw);
        for ($index = 0; $index < $length; $index++) {
            if ($raw[$index] !== '%') {
                continue;
            }
            $digits = substr($raw, $index + 1, 2);
            if (strlen($digits) < 2 || preg_match('/^[0-9a-fA-F]{2}$/', $digits) !== 1) {
                return true;
            }
            $index += 2;
        }

        return false;
    }
}
