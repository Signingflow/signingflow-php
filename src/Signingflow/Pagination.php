<?php

declare(strict_types=1);

namespace Signingflow;

final class ApiList
{
    public const MAX_PAGES = 100;

    /** @param list<mixed> $data */
    public function __construct(
        public array $data,
        public string $nextPageToken = '',
        public mixed $load = null,
    ) {
    }

    public function all(): \Generator
    {
        $page = $this;
        $load = $page->load;
        $seen = [];
        $pages = 0;
        while (true) {
            foreach ($page->data as $item) {
                yield $item;
            }
            $token = $page->nextPageToken;
            if ($token === '' || $load === null) {
                return;
            }
            if (isset($seen[$token])) {
                return;
            }
            $pages++;
            if ($pages > self::MAX_PAGES) {
                throw new InvalidRequestError('Too many pages.');
            }
            $seen[$token] = true;
            $page = $load($token);
        }
    }
}

final class Pagination
{
    public static function nextToken(mixed $body): string
    {
        $record = Status::asMap($body);
        if ($record === null) {
            return '';
        }
        $value = Status::asStr($record['next_page_token'] ?? null);
        if ($value !== '') {
            return $value;
        }

        return Status::asStr($record['nextPageToken'] ?? null);
    }

    /** @return list<array<string, mixed>> */
    public static function items(mixed $body, string $key): array
    {
        $record = Status::asMap($body);
        if ($record === null) {
            return [];
        }
        $raw = $record[$key] ?? null;
        if (!is_array($raw)) {
            return [];
        }
        $items = [];
        foreach ($raw as $item) {
            $row = Status::asMap($item);
            if ($row !== null) {
                $items[] = $row;
            }
        }

        return $items;
    }

    public static function pageSize(mixed $value): int
    {
        if ($value === null) {
            return 10;
        }
        if (is_bool($value) || !is_int($value) || $value < 1 || $value > 1000) {
            throw new InvalidRequestError('pageSize must be a whole number from 1 to 1000.');
        }

        return $value;
    }
}
