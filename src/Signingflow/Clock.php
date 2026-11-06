<?php

declare(strict_types=1);

namespace Signingflow;

final class Clock
{
    public static ?\Closure $nowFn = null;

    public static ?\Closure $sleepFn = null;

    public static function now(): \DateTimeImmutable
    {
        if (self::$nowFn !== null) {
            return (self::$nowFn)();
        }

        return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public static function sleep(float $seconds): void
    {
        if (self::$sleepFn !== null) {
            (self::$sleepFn)($seconds);

            return;
        }
        if ($seconds > 0) {
            usleep((int) round($seconds * 1_000_000));
        }
    }

    public static function reset(): void
    {
        self::$nowFn = null;
        self::$sleepFn = null;
    }
}
