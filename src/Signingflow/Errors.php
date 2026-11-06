<?php

declare(strict_types=1);

namespace Signingflow;

class FieldViolation
{
    public function __construct(
        public string $field,
        public string $description,
    ) {
    }
}

class Error extends \Exception
{
    public function __construct(
        string $message = '',
        public int $statusCode = 0,
        public ?int $grpcCode = null,
        public string $traceCode = '',
        public string $requestId = '',
        public string $idempotencyKey = '',
        public string $capability = '',
        public string $resourceName = '',
        public string $envelopeName = '',
        public string $retryAfter = '',
        public array $fieldViolations = [],
    ) {
        parent::__construct($message);
    }
}

class AuthenticationError extends Error
{
}

class PermissionError extends Error
{
}

class IdempotencyError extends Error
{
}

class RateLimitError extends Error
{
}

class InvalidRequestError extends Error
{
}

class APIError extends Error
{
}

class ConnectionError extends Error
{
}

class SignatureVerificationError extends Error
{
}
