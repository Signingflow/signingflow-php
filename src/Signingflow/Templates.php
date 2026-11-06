<?php

declare(strict_types=1);

namespace Signingflow;

final class Templates
{
    public function __construct(private Sender $sender)
    {
    }

    public function use(string $template, string $idempotencyKey = ''): Envelope
    {
        $name = Models::requireTemplateName($template);
        $created = $this->sender->call(
            'TemplateService_UseTemplate',
            pathParams: ['name' => $name],
            body: [],
            idempotencyKey: $idempotencyKey,
        );

        return Models::createdEnvelope($created);
    }
}
