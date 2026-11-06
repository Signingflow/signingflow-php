<?php

declare(strict_types=1);

namespace Signingflow;

final class Envelope
{
    public function __construct(
        public string $name = '',
        public string $uid = '',
        public string $displayName = '',
        public string $description = '',
        public string $progressStatus = '',
        public string $state = '',
        public string $condition = '',
        public string $sentTime = '',
        public array $documents = [],
        public ?array $compliance = null,
        public ?array $progress = null,
    ) {
    }
}

final class Download
{
    public function __construct(
        public string $uri = '',
        public string $downloadTime = '',
        public string $etag = '',
    ) {
    }
}

final class StoredFile
{
    public function __construct(
        public string $name,
        public string $id,
    ) {
    }
}

final class Models
{
    private const ENVELOPE_NAME = '/^envelopes\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    private const TEMPLATE_NAME = '/^templates\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    private const WEBHOOK_NAME = '/^webhookUrls\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    private const DELIVERY_NAME = '/^webhooks\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    private const STORAGE_ID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    private const EMAIL = '/^[^\s@]+@[^\s@]+$/';

    public static function requireEnvelopeName(string $name): string
    {
        $name = trim($name);
        if (preg_match(self::ENVELOPE_NAME, $name) !== 1) {
            throw new InvalidRequestError('envelope must look like envelopes/{id}.');
        }

        return $name;
    }

    public static function requireTemplateName(string $name): string
    {
        $name = trim($name);
        if (preg_match(self::TEMPLATE_NAME, $name) !== 1) {
            throw new InvalidRequestError('template must look like templates/{id}.');
        }

        return $name;
    }

    public static function webhookName(string $name): string
    {
        $name = trim($name);
        if (preg_match(self::WEBHOOK_NAME, $name) !== 1) {
            throw new InvalidRequestError('webhook url must look like webhookUrls/{id}.');
        }

        return $name;
    }

    public static function deliveryName(string $name): string
    {
        $name = trim($name);
        if (preg_match(self::DELIVERY_NAME, $name) !== 1) {
            throw new InvalidRequestError('webhook delivery must look like webhooks/{id}.');
        }

        return $name;
    }

    /** @return list<array{name: string, email: string}> */
    public static function cleanRecipients(mixed $recipients): array
    {
        $people = [];
        foreach ($recipients ?? [] as $person) {
            if (!is_array($person)) {
                $people[] = ['name' => '', 'email' => ''];
                continue;
            }
            $people[] = [
                'name' => trim(Status::asStr($person['name'] ?? null)),
                'email' => trim(Status::asStr($person['email'] ?? null)),
            ];
        }
        if ($people === []) {
            throw new InvalidRequestError('Each recipient needs a name and an email.');
        }
        foreach ($people as $person) {
            if ($person['name'] === '' || preg_match(self::EMAIL, $person['email']) !== 1) {
                throw new InvalidRequestError('Each recipient needs a name and an email.');
            }
        }

        return $people;
    }

    public static function firstString(mixed $record, string ...$keys): string
    {
        $map = Status::asMap($record);
        if ($map === null) {
            return '';
        }
        foreach ($keys as $key) {
            $value = Status::asStr($map[$key] ?? null);
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    public static function decodeEnvelope(mixed $body): Envelope
    {
        $record = Status::asMap($body) ?? [];
        $nested = Status::asMap($record['envelope'] ?? null);
        if ($nested !== null) {
            $record = $nested;
        }
        $documents = [];
        $rawDocs = $record['documents'] ?? null;
        if (is_array($rawDocs)) {
            foreach ($rawDocs as $item) {
                $doc = Status::asMap($item);
                if ($doc !== null) {
                    $documents[] = $doc;
                }
            }
        }

        return new Envelope(
            name: Status::asStr($record['name'] ?? null),
            uid: Status::asStr($record['uid'] ?? null),
            displayName: self::firstString($record, 'display_name', 'displayName'),
            description: Status::asStr($record['description'] ?? null),
            progressStatus: self::firstString($record, 'progress_status', 'progressStatus'),
            state: Status::asStr($record['state'] ?? null),
            condition: Status::asStr($record['condition'] ?? null),
            sentTime: self::firstString($record, 'sent_time', 'sentTime'),
            documents: $documents,
            compliance: Status::asMap($record['compliance'] ?? null),
            progress: Status::asMap($record['progress'] ?? null),
        );
    }

    public static function envelopeNameOf(mixed $body): string
    {
        $record = Status::asMap($body) ?? [];
        $nested = Status::asMap($record['envelope'] ?? null) ?? [];
        $name = Status::asStr($nested['name'] ?? null);
        if ($name === '') {
            $name = Status::asStr($record['name'] ?? null);
        }
        if (str_starts_with($name, 'envelopes/')) {
            return $name;
        }
        $uid = Status::asStr($nested['uid'] ?? null);
        if ($uid === '') {
            $uid = Status::asStr($record['uid'] ?? null);
        }
        if ($uid === '') {
            return '';
        }

        return 'envelopes/'.$uid;
    }

    public static function createdEnvelope(mixed $body): Envelope
    {
        $envelope = self::decodeEnvelope($body);
        $name = self::envelopeNameOf($body);
        if ($name !== '') {
            $envelope->name = $name;
        } elseif ($envelope->name === '' && $envelope->uid !== '') {
            $envelope->name = 'envelopes/'.$envelope->uid;
        }

        return $envelope;
    }

    public static function envelopeState(Envelope $envelope): string
    {
        if ($envelope->progress !== null) {
            $state = Status::asStr($envelope->progress['state'] ?? null);
            if ($state !== '') {
                return $state;
            }
        }
        if ($envelope->progressStatus !== '') {
            return $envelope->progressStatus;
        }
        if ($envelope->state !== '') {
            return $envelope->state;
        }

        return $envelope->condition;
    }

    /** @return array{0: string, 1: string, 2: string}|null */
    public static function findStorage(mixed $body): ?array
    {
        $record = Status::asMap($body);
        if ($record !== null && array_key_exists('storages', $record)) {
            $found = self::findStorage($record['storages']);
            if ($found !== null) {
                return $found;
            }
        }

        return self::walkStorage($body);
    }

    /** @return array{0: string, 1: string, 2: string}|null */
    private static function walkStorage(mixed $body): ?array
    {
        if (Status::asMap($body) !== null) {
            $rawUrl = self::firstString($body, 'pre_signed_url', 'preSignedUrl');
            $name = Status::asStr($body['name'] ?? null);
            $fileId = str_contains($name, '/') ? substr($name, strrpos($name, '/') + 1) : $name;
            if (str_starts_with($name, 'storages/') && preg_match(self::STORAGE_ID, $fileId) === 1 && $rawUrl !== '') {
                return [$name, $fileId, $rawUrl];
            }
            foreach ($body as $key => $child) {
                if ($key === 'storages') {
                    continue;
                }
                $found = self::walkStorage($child);
                if ($found !== null) {
                    return $found;
                }
            }

            return null;
        }
        if (is_array($body)) {
            foreach ($body as $child) {
                $found = self::walkStorage($child);
                if ($found !== null) {
                    return $found;
                }
            }
        }

        return null;
    }
}
