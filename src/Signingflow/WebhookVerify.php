<?php

declare(strict_types=1);

namespace Signingflow;

final class Event
{
    public function __construct(
        public mixed $payload,
        public string $bodySha256,
    ) {
    }
}

final class WebhookVerify
{
    public static function construct(
        mixed $payload,
        mixed $signature,
        mixed $secret,
        mixed $previousSecret = '',
        mixed $previousSignature = '',
    ): Event {
        if (!is_string($payload)) {
            throw new SignatureVerificationError('Pass the raw request body.');
        }
        if (!is_string($secret) || $secret === '') {
            throw new SignatureVerificationError('Webhook secret is required.');
        }
        $signature = is_string($signature) ? $signature : '';
        $previousSecret = is_string($previousSecret) ? $previousSecret : '';
        $previousSignature = is_string($previousSignature) ? $previousSignature : '';
        $current = $signature !== '' && self::equals($signature, self::mac($secret, $payload));
        $previous = $previousSecret !== '' && $previousSignature !== '' && self::equals($previousSignature, self::mac($previousSecret, $payload));
        if (!$current && !$previous) {
            throw new SignatureVerificationError('Webhook signature did not match.');
        }
        try {
            $decoded = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new InvalidRequestError('The webhook body is not JSON.');
        }

        return new Event($decoded, hash('sha256', $payload));
    }

    private static function mac(string $secret, string $body): string
    {
        return hash_hmac('sha256', $body, $secret);
    }

    private static function equals(string $left, string $right): bool
    {
        $a = strtolower($left);
        $b = strtolower($right);
        if (strlen($a) !== strlen($b)) {
            hash_equals($a, $a);

            return false;
        }

        return hash_equals($a, $b);
    }
}
