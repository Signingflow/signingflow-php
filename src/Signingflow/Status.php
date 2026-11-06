<?php

declare(strict_types=1);

namespace Signingflow;

final class Status
{
    public static function asMap(mixed $value): ?array
    {
        return is_array($value) && !array_is_list($value) ? $value : null;
    }

    public static function asStr(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }

    public static function asInt(mixed $value): ?int
    {
        if (is_bool($value)) {
            return null;
        }
        if (is_int($value)) {
            return $value;
        }
        if (is_float($value)) {
            return (int) $value;
        }
        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }

        return null;
    }

    public static function grpcCode(mixed $body): ?int
    {
        $record = self::asMap($body);
        if ($record === null) {
            return null;
        }

        return self::asInt($record['code'] ?? null);
    }

    public static function serverMessage(mixed $body): string
    {
        if (is_string($body)) {
            return $body;
        }
        $record = self::asMap($body);
        if ($record === null) {
            return '';
        }

        return self::asStr($record['message'] ?? null);
    }

    public static function traceCode(mixed $body): string
    {
        return self::findMeta($body, 'trace_code');
    }

    public static function resourceName(mixed $body): string
    {
        $url = self::findMeta($body, 'resource_url');
        if ($url !== '') {
            return $url;
        }

        return self::findMeta($body, 'resource_id');
    }

    /** @return list<FieldViolation> */
    public static function fieldViolations(mixed $body): array
    {
        $found = [];
        self::walk($body, static function (array $record) use (&$found): void {
            $items = $record['fieldViolations'] ?? $record['field_violations'] ?? null;
            if (!is_array($items)) {
                return;
            }
            foreach ($items as $item) {
                $row = self::asMap($item);
                if ($row === null) {
                    continue;
                }
                $field = self::asStr($row['field'] ?? null);
                $description = self::asStr($row['description'] ?? null);
                if ($field !== '' || $description !== '') {
                    $found[] = new FieldViolation($field, $description);
                }
            }
        });

        return $found;
    }

    public static function mentionsIdempotency(mixed $body): bool
    {
        try {
            $encoded = json_encode($body, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return false;
        }

        return str_contains(strtolower($encoded), 'idempotency');
    }

    private static function findMeta(mixed $body, string $key): string
    {
        $found = '';
        self::walk($body, static function (array $record) use (&$found, $key): void {
            if ($found !== '') {
                return;
            }
            $meta = self::asMap($record['metadata'] ?? null);
            if ($meta === null) {
                return;
            }
            $value = self::asStr($meta[$key] ?? null);
            if ($value !== '') {
                $found = $value;
            }
        });

        return $found;
    }

    private static function walk(mixed $value, \Closure $visit): void
    {
        if (self::asMap($value) !== null) {
            $visit($value);
            foreach ($value as $child) {
                self::walk($child, $visit);
            }

            return;
        }
        if (is_array($value)) {
            foreach ($value as $child) {
                self::walk($child, $visit);
            }
        }
    }
}
