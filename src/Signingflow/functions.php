<?php

declare(strict_types=1);

namespace Signingflow;

function constructEvent(
    mixed $payload,
    mixed $signature,
    mixed $secret,
    mixed $previousSecret = '',
    mixed $previousSignature = '',
): Event {
    return WebhookVerify::construct($payload, $signature, $secret, $previousSecret, $previousSignature);
}

function signingSecretOf(mixed $body): string
{
    return WebhookUrls::signingSecretOf($body);
}
