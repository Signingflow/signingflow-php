<?php

declare(strict_types=1);

namespace Signingflow;

final class Allowlist
{
    /** @var array<string, array<string, mixed>> */
    private static array $byId = [];

    public static function operation(string $id): array
    {
        $all = self::load();
        if (!isset($all[$id])) {
            throw new Error('Unknown operation.');
        }

        return $all[$id];
    }

    /** @return array<string, array<string, mixed>> */
    private static function load(): array
    {
        if (self::$byId !== []) {
            return self::$byId;
        }
        $path = __DIR__.'/resources/allowlist.json';
        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException('The allowlist could not be read.');
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded) || !isset($decoded['operations']) || !is_array($decoded['operations'])) {
            throw new \RuntimeException('The allowlist is invalid.');
        }
        if (count($decoded['operations']) !== 15) {
            throw new \RuntimeException('The allowlist is invalid.');
        }
        $byId = [];
        foreach ($decoded['operations'] as $operation) {
            if (!is_array($operation) || !isset($operation['operationId'])) {
                throw new \RuntimeException('The allowlist is invalid.');
            }
            $byId[(string) $operation['operationId']] = $operation;
        }
        if (count($byId) !== 15) {
            throw new \RuntimeException('The allowlist is invalid.');
        }
        self::$byId = $byId;

        return self::$byId;
    }
}
