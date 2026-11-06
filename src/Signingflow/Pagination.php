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

    public function all(): \Iterator
    {
        return new ApiListIterator($this);
    }
}

final class ApiListIterator implements \Iterator
{
    private ApiList $page;

    private mixed $load;

    private int $index = 0;

    private int $pages = 0;

    private int $position = 0;

    private bool $finished = false;

    /** @var array<string, true> */
    private array $seen = [];

    public function __construct(ApiList $first)
    {
        $this->page = $first;
        $this->load = $first->load;
    }

    public function rewind(): void
    {
        if ($this->position !== 0 || $this->index !== 0 || $this->pages !== 0) {
            throw new \LogicException('An API list can only be iterated once.');
        }
    }

    public function valid(): bool
    {
        if ($this->finished) {
            return false;
        }
        $this->pull();

        return !$this->finished && $this->index < count($this->page->data);
    }

    public function current(): mixed
    {
        return $this->page->data[$this->index];
    }

    public function key(): int
    {
        return $this->position;
    }

    public function next(): void
    {
        $this->index++;
        $this->position++;
        $this->pull();
    }

    private function pull(): void
    {
        while (!$this->finished && $this->index >= count($this->page->data)) {
            $token = $this->page->nextPageToken;
            if ($token === '' || $this->load === null || isset($this->seen[$token])) {
                $this->finished = true;

                return;
            }
            $this->pages++;
            if ($this->pages > ApiList::MAX_PAGES) {
                throw new InvalidRequestError('Too many pages.');
            }
            $this->seen[$token] = true;
            $this->page = ($this->load)($token);
            $this->index = 0;
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
