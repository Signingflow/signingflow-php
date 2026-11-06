<?php

declare(strict_types=1);

namespace Signingflow;

final class JailError extends \Exception
{
    public function __construct(public string $reason)
    {
        parent::__construct($reason);
    }
}

final class Jail
{
    public const MAX_BYTES = 25 * 1024 * 1024;

    /** @internal Test seam. Null uses the platform flag. */
    public static ?int $nofollowOverride = null;

    /** @internal Test seam. When true, path reads fail before open. */
    public static bool $ffiDisabled = false;

    public static function read(string $uploadRoot, string $requested, int $maxBytes = self::MAX_BYTES): string
    {
        if (trim($uploadRoot) === '') {
            throw new InvalidRequestError('A filesystem path requires upload_root.');
        }
        try {
            return self::readJailed($uploadRoot, $requested, $maxBytes);
        } catch (JailError $error) {
            if ($error->reason === 'too large') {
                throw new InvalidRequestError('The file is larger than 25 MB.');
            }
            if ($error->reason === 'outside root') {
                throw new InvalidRequestError('The path is outside upload_root.');
            }
            if ($error->reason === 'hard link') {
                throw new InvalidRequestError('The file must not be a hard link.');
            }
            throw new InvalidRequestError('The file could not be read.');
        }
    }

    public static function reset(): void
    {
        self::$nofollowOverride = null;
        self::$ffiDisabled = false;
    }

    private static function readJailed(string $root, string $requested, int $maxBytes): string
    {
        $flags = self::flags();
        if ($flags['nofollow'] === 0 || $flags['nonblock'] === 0) {
            throw new JailError('nofollow');
        }
        if ($requested === '' || str_contains($requested, "\0") || self::isAbsolute($requested)) {
            throw new JailError('outside root');
        }
        foreach (preg_split('#[/\\\\]#', $requested) ?: [] as $segment) {
            if ($segment === '..') {
                throw new JailError('outside root');
            }
        }
        $base = realpath($root);
        if ($base === false) {
            throw new JailError('open');
        }
        $resolved = self::normpath($base.'/'.$requested);
        if (self::escapes($base, $resolved) || self::normpath($resolved) === self::normpath($base)) {
            throw new JailError('outside root');
        }
        $parent = dirname($resolved);
        $parentReal = realpath($parent);
        if ($parentReal === false || self::escapes($base, $parentReal)) {
            throw new JailError('outside root');
        }
        $leaf = basename($resolved);
        if ($leaf === '' || $leaf === '.' || $leaf === '..') {
            throw new JailError('outside root');
        }
        $path = $parentReal.'/'.$leaf;
        if (self::escapes($base, $path) || self::normpath($path) === self::normpath($base)) {
            throw new JailError('outside root');
        }

        $ffi = self::ffi();
        $fd = $ffi->open($path, $flags['rdonly'] | $flags['nofollow'] | $flags['nonblock']);
        if ($fd < 0) {
            throw new JailError('open');
        }
        $stream = @fopen('php://fd/'.$fd, 'rb');
        try {
            if ($stream === false) {
                throw new JailError('open');
            }
            $info = fstat($stream);
            if ($info === false) {
                throw new JailError('open');
            }
            $mode = (int) $info['mode'];
            if (($mode & 0170000) !== 0100000) {
                throw new JailError('not a file');
            }
            if ((int) $info['nlink'] > 1) {
                throw new JailError('hard link');
            }
            if ((int) $info['size'] > $maxBytes) {
                throw new JailError('too large');
            }
            if ((int) $info['size'] === 0) {
                return '';
            }
            $data = stream_get_contents($stream, (int) $info['size']);
            if (!is_string($data) || strlen($data) !== (int) $info['size']) {
                throw new JailError('short');
            }

            return $data;
        } finally {
            if (is_resource($stream)) {
                fclose($stream);
            }
            @$ffi->close($fd);
        }
    }

    /** @return array{nofollow: int, nonblock: int, rdonly: int} */
    private static function flags(): array
    {
        if (self::$nofollowOverride !== null) {
            return ['nofollow' => self::$nofollowOverride, 'nonblock' => 1, 'rdonly' => 0];
        }
        if (PHP_OS_FAMILY === 'Darwin') {
            return ['nofollow' => 0x100, 'nonblock' => 0x4, 'rdonly' => 0];
        }
        if (PHP_OS_FAMILY === 'Linux') {
            return ['nofollow' => 0400000, 'nonblock' => 04000, 'rdonly' => 0];
        }

        return ['nofollow' => 0, 'nonblock' => 0, 'rdonly' => 0];
    }

    private static function ffi(): \FFI
    {
        if (self::$ffiDisabled || !class_exists(\FFI::class)) {
            throw new JailError('nofollow');
        }
        try {
            return \FFI::cdef(
                'int open(const char *path, int flags); int close(int fd);',
            );
        } catch (\Throwable) {
            throw new JailError('nofollow');
        }
    }

    private static function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/')
            || str_starts_with($path, '\\')
            || preg_match('/^[A-Za-z]:/', $path) === 1;
    }

    private static function normpath(string $path): string
    {
        $absolute = str_starts_with($path, '/');
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                if ($parts !== []) {
                    array_pop($parts);
                }
                continue;
            }
            $parts[] = $part;
        }
        $out = ($absolute ? '/' : '').implode('/', $parts);

        return $out === '' ? ($absolute ? '/' : '.') : $out;
    }

    private static function escapes(string $base, string $target): bool
    {
        $base = rtrim($base, '/');
        $target = rtrim($target, '/');
        if ($target === $base) {
            return false;
        }

        return !str_starts_with($target, $base.'/');
    }
}
