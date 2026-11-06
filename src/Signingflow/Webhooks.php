<?php

declare(strict_types=1);

namespace Signingflow;

final class HttpConfig
{
    public function __construct(public string $auth = '')
    {
    }
}

final class WebhookUrl
{
    public function __construct(
        public string $name = '',
        public string $displayName = '',
        public string $httpRequestUri = '',
        public array $events = [],
        public string $signingSecret = '',
    ) {
    }
}

final class WebhookDelivery
{
    public function __construct(
        public string $name = '',
        public string $event = '',
    ) {
    }
}

final class WebhookUrls
{
    public function __construct(private Sender $sender)
    {
    }

    public function create(array $params): WebhookUrl
    {
        $displayName = trim((string) ($params['display_name'] ?? ''));
        if (strlen($displayName) < 1 || strlen($displayName) > 100) {
            throw new InvalidRequestError('display_name must be 1 to 100 characters.');
        }
        $uri = (string) ($params['http_request_uri'] ?? '');
        $parsed = parse_url($uri);
        if (!is_array($parsed) || empty($parsed['host']) || ($parsed['scheme'] ?? '') !== 'https') {
            throw new InvalidRequestError('http_request_uri must be an https URL.');
        }
        $events = $params['events'] ?? null;
        if (!is_array($events) || $events === []) {
            throw new InvalidRequestError('events is required.');
        }
        $httpConfig = $params['http_config'] ?? null;
        if ($httpConfig !== null) {
            $auth = '';
            if ($httpConfig instanceof HttpConfig) {
                $auth = $httpConfig->auth;
            } elseif (is_object($httpConfig) && isset($httpConfig->auth)) {
                $auth = (string) $httpConfig->auth;
            }
            if (strtoupper($auth) === 'NONE') {
                throw new InvalidRequestError('auth NONE has no signature. Leave http_config empty.');
            }
            throw new InvalidRequestError('Leave http_config empty so the destination uses HMAC.');
        }
        $created = $this->sender->call(
            'WebhookUrlService_AddWebhookUrl',
            body: [
                'webhookUrl' => [
                    'displayName' => $displayName,
                    'httpRequestUri' => $uri,
                    'events' => array_values($events),
                ],
            ],
            idempotencyKey: (string) ($params['idempotency_key'] ?? ''),
        );

        return self::decode($created, false);
    }

    public function retrieve(string $name): WebhookUrl
    {
        $destination = Models::webhookName($name);
        $viewed = $this->sender->call('WebhookUrlService_ViewWebhookUrl', pathParams: ['name' => $destination]);

        return self::decode($viewed, true);
    }

    public function test(string $name): WebhookUrl
    {
        $destination = Models::webhookName($name);
        $tested = $this->sender->call('WebhookUrlService_TestWebhookUrl', pathParams: ['name' => $destination], body: []);

        return self::decode($tested, false);
    }

    public static function signingSecretOf(mixed $body): string
    {
        if ($body instanceof WebhookUrl) {
            return $body->signingSecret;
        }
        $record = Status::asMap($body);
        if ($record === null && is_object($body)) {
            $record = get_object_vars($body);
        }
        if (!is_array($record)) {
            return '';
        }
        $secret = Status::asStr($record['signing_secret'] ?? null);
        if ($secret !== '') {
            return $secret;
        }

        return Status::asStr($record['signingSecret'] ?? null);
    }

    private static function decode(mixed $body, bool $dropSecret): WebhookUrl
    {
        $record = Status::asMap($body) ?? [];
        if ($dropSecret) {
            unset($record['signing_secret'], $record['signingSecret']);
        }
        $events = [];
        $rawEvents = $record['events'] ?? null;
        if (is_array($rawEvents)) {
            foreach ($rawEvents as $event) {
                $text = Status::asStr($event);
                if ($text !== '') {
                    $events[] = $text;
                }
            }
        }

        return new WebhookUrl(
            name: Status::asStr($record['name'] ?? null),
            displayName: Models::firstString($record, 'displayName', 'display_name'),
            httpRequestUri: Models::firstString($record, 'httpRequestUri', 'http_request_uri'),
            events: $events,
            signingSecret: self::signingSecretOf($record),
        );
    }
}

final class WebhookDeliveries
{
    public function __construct(private Sender $sender)
    {
    }

    public function list(array $params = []): ApiList
    {
        $size = Pagination::pageSize($params['page_size'] ?? null);
        $load = function (string $token) use ($size): ApiList {
            return $this->listPage($size, $token);
        };
        $page = $load((string) ($params['page_token'] ?? ''));
        $page->load = $load;

        return $page;
    }

    public function retrieve(string $name): WebhookDelivery
    {
        $delivery = Models::deliveryName($name);
        $viewed = $this->sender->call('WebhookService_ViewWebhook', pathParams: ['name' => $delivery]);
        $record = Status::asMap($viewed) ?? [];

        return new WebhookDelivery(
            name: Status::asStr($record['name'] ?? null),
            event: Status::asStr($record['event'] ?? null),
        );
    }

    private function listPage(int $pageSize, string $pageToken): ApiList
    {
        $body = $this->sender->call(
            'WebhookService_ListWebhooks',
            pathParams: ['parent' => 'webhooks'],
            query: [
                'pageSize' => (string) $pageSize,
                'pageToken' => $pageToken,
            ],
        );
        $record = Status::asMap($body) ?? [];
        $data = [];
        foreach (Pagination::items($record, 'webhooks') as $item) {
            $data[] = new WebhookDelivery(
                name: Status::asStr($item['name'] ?? null),
                event: Status::asStr($item['event'] ?? null),
            );
        }

        return new ApiList($data, Pagination::nextToken($record));
    }
}
