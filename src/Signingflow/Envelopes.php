<?php

declare(strict_types=1);

namespace Signingflow;

final class Envelopes
{
    public function __construct(
        private Sender $sender,
        private Files $files,
        private Templates $templates,
    ) {
    }

    public function create(array $params): Envelope
    {
        $title = trim((string) ($params['display_name'] ?? ''));
        if ($title === '') {
            throw new InvalidRequestError('Name the draft title.');
        }
        $storageId = trim((string) ($params['storage_id'] ?? ''));
        if ($storageId === '') {
            throw new InvalidRequestError('storage_id is required.');
        }
        $created = $this->sender->call(
            'EnvelopeService_AddEnvelope',
            body: [
                'envelope' => [
                    'display_name' => $title,
                    'description' => trim((string) ($params['description'] ?? '')),
                    'documents' => [[
                        'display_name' => $title,
                        'attachments' => [['storage_id' => $storageId]],
                        'supplemental' => false,
                    ]],
                ],
            ],
            idempotencyKey: (string) ($params['idempotency_key'] ?? ''),
        );

        return Models::createdEnvelope($created);
    }

    public function retrieve(string $name, string $readMask = ''): Envelope
    {
        $envelope = Models::requireEnvelopeName($name);
        $viewed = $this->sender->call(
            'EnvelopeService_ViewEnvelope',
            pathParams: ['name' => $envelope],
            query: ['readMask' => $readMask],
        );
        $decoded = Models::decodeEnvelope($viewed);
        if ($decoded->name === '') {
            $decoded->name = $envelope;
        }

        return $decoded;
    }

    public function update(string $name, array $body): Envelope
    {
        $envelope = Models::requireEnvelopeName($name);
        if (Status::asStr($body['name'] ?? null) === '') {
            $body['name'] = $envelope;
        }
        $updated = $this->sender->call(
            'EnvelopeService_UpdateEnvelope',
            pathParams: ['name' => $envelope],
            body: $body,
        );

        return Models::decodeEnvelope($updated);
    }

    public function send(string $name, string $idempotencyKey = ''): Envelope
    {
        $envelope = Models::requireEnvelopeName($name);
        $sent = $this->sender->call(
            'EnvelopeService_SendEnvelope',
            pathParams: ['name' => $envelope],
            body: [],
            idempotencyKey: $idempotencyKey,
        );
        $decoded = Models::decodeEnvelope($sent);
        if ($decoded->name === '') {
            $decoded->name = $envelope;
        }

        return $decoded;
    }

    public function list(array $params): ApiList
    {
        $directory = trim((string) ($params['directory'] ?? ''));
        if ($directory === '') {
            throw new InvalidRequestError('directory is required.');
        }
        $size = Pagination::pageSize($params['page_size'] ?? null);
        $readMask = (string) ($params['read_mask'] ?? '');
        $load = function (string $token) use ($directory, $size, $readMask): ApiList {
            return $this->listPage($directory, $size, $token, $readMask);
        };
        $page = $load((string) ($params['page_token'] ?? ''));
        $page->load = $load;

        return $page;
    }

    public function remind(string $name): Envelope
    {
        $envelope = Models::requireEnvelopeName($name);
        $reminded = $this->sender->call(
            'EnvelopeService_RemindEnvelopeSigners',
            pathParams: ['name' => $envelope],
            body: [],
        );
        $decoded = Models::decodeEnvelope($reminded);
        if ($decoded->name === '') {
            $decoded->name = $envelope;
        }

        return $decoded;
    }

    public function download(string $name): Download
    {
        $envelope = Models::requireEnvelopeName($name);
        $downloaded = $this->sender->call(
            'EnvelopeService_DownloadEnvelope',
            pathParams: ['name' => $envelope],
        );
        $record = Status::asMap($downloaded) ?? [];

        return new Download(
            uri: Status::asStr($record['uri'] ?? null),
            downloadTime: Models::firstString($record, 'download_time', 'downloadTime'),
            etag: Status::asStr($record['etag'] ?? null),
        );
    }

    public function prepareDraft(array $params): Envelope
    {
        $title = trim((string) ($params['title'] ?? ''));
        if ($title === '') {
            throw new InvalidRequestError('Name the PDF and the draft title.');
        }
        $stored = $this->files->create($params);

        return $this->create([
            'display_name' => $title,
            'description' => (string) ($params['message'] ?? ''),
            'storage_id' => $stored->id,
        ]);
    }

    public function sendDocument(array $params): Envelope
    {
        $title = trim((string) ($params['title'] ?? ''));
        if ($title === '') {
            throw new InvalidRequestError('Name the PDF, the title, and the recipients.');
        }
        $people = Models::cleanRecipients($params['recipients'] ?? null);
        $stored = $this->files->create($params);
        $created = $this->create([
            'display_name' => $title,
            'description' => (string) ($params['message'] ?? ''),
            'storage_id' => $stored->id,
        ]);

        return $this->finishSend($created, $people, (string) ($params['message'] ?? ''), $title);
    }

    public function sendFromTemplate(array $params): Envelope
    {
        $people = Models::cleanRecipients($params['recipients'] ?? null);
        $template = (string) ($params['template'] ?? '');
        $created = $this->templates->use($template);

        return $this->finishSend($created, $people, (string) ($params['message'] ?? ''), $template);
    }

    public function downloadCompleted(string $name): Download
    {
        $envelope = Models::requireEnvelopeName($name);
        $viewed = $this->retrieve($envelope);
        if (strtoupper(trim(Models::envelopeState($viewed))) !== 'COMPLETED') {
            $error = new InvalidRequestError('The signed file is not ready.');
            $error->envelopeName = $envelope;
            throw $error;
        }

        return $this->download($envelope);
    }

    private function listPage(string $directory, int $pageSize, string $pageToken, string $readMask): ApiList
    {
        $body = $this->sender->call(
            'EnvelopeService_ListEnvelopes',
            pathParams: ['parent' => 'envelopes'],
            query: [
                'directory' => $directory,
                'pageSize' => (string) $pageSize,
                'pageToken' => $pageToken,
                'readMask' => $readMask,
            ],
        );
        $record = Status::asMap($body) ?? [];
        $data = [];
        foreach (Pagination::items($record, 'envelopes') as $item) {
            $data[] = Models::decodeEnvelope($item);
        }

        return new ApiList($data, Pagination::nextToken($record));
    }

    /** @param list<array{name: string, email: string}> $people */
    private function finishSend(Envelope $created, array $people, string $message, string $label): Envelope
    {
        $name = $created->name;
        try {
            Models::requireEnvelopeName($name);
        } catch (\Throwable) {
            throw new APIError($label.' was saved without an envelope name.');
        }
        try {
            $viewed = $this->retrieve($name, 'documents,compliance');
        } catch (Error $error) {
            throw $this->attached($error, $name);
        }
        $patched = $this->withRecipients($viewed, $people, $message);
        if ($patched === null) {
            $error = new InvalidRequestError('The draft has no document to address.');
            $error->envelopeName = $name;
            throw $error;
        }
        try {
            $this->update($name, $patched);
        } catch (Error $error) {
            throw $this->attached($error, $name);
        }

        return $this->sendOrView($name);
    }

    private function sendOrView(string $name): Envelope
    {
        $started = Clock::now();
        try {
            return $this->send($name);
        } catch (IdempotencyError $error) {
            if ($error->resourceName === $name) {
                try {
                    return $this->retrieve($name);
                } catch (\Throwable) {
                    throw $this->attached($error, $name);
                }
            }
            throw $this->attached($error, $name);
        } catch (ConnectionError $error) {
            try {
                $viewed = $this->retrieve($name);
            } catch (\Throwable) {
                throw $this->attached($error, $name);
            }
            $sent = Path::parseRetry($viewed->sentTime);
            if ($sent !== null && self::sentDuring($sent, $started, Clock::now())) {
                return $viewed;
            }
            throw $this->attached($error, $name);
        } catch (Error $error) {
            throw $this->attached($error, $name);
        }
    }

    /** @param list<array{name: string, email: string}> $people
     * @return array<string, mixed>|null
     */
    private function withRecipients(Envelope $envelope, array $people, string $message): ?array
    {
        $refs = [];
        foreach ($envelope->documents as $item) {
            if (!is_array($item)) {
                continue;
            }
            $uid = Models::firstString($item, 'uid', 'id');
            if ($uid === '') {
                continue;
            }
            $refs[] = ['uid' => $uid, 'display_name' => Models::firstString($item, 'display_name', 'displayName')];
        }
        if ($refs === []) {
            return null;
        }
        $participants = [];
        foreach ($people as $index => $person) {
            $participants[] = [
                'uid' => Sender::uuid4(),
                'display_name' => $person['name'],
                'alternate_email' => $person['email'],
                'role' => 'SIGNER',
                'type' => 'PERSONAL',
                'action_order_type' => 'SERIAL',
                'action_order_number' => $index + 1,
            ];
        }
        $profile = 'STANDARD';
        if ($envelope->compliance !== null && Status::asStr($envelope->compliance['profile'] ?? null) !== '') {
            $profile = Status::asStr($envelope->compliance['profile']);
        }
        $description = trim($message) !== '' ? trim($message) : $envelope->description;
        $documents = [];
        foreach ($refs as $index => $document) {
            $item = ['uid' => $document['uid'], 'display_name' => $document['display_name']];
            if ($index === 0) {
                $item['participants'] = $participants;
            }
            $documents[] = $item;
        }

        return [
            'name' => $envelope->name,
            'display_name' => $envelope->displayName,
            'description' => $description,
            'compliance' => ['profile' => $profile],
            'documents' => $documents,
        ];
    }

    private function attached(Error $error, string $name): Error
    {
        $error->envelopeName = $name;

        return $error;
    }

    private static function sentDuring(\DateTimeImmutable $sent, \DateTimeImmutable $started, \DateTimeImmutable $current): bool
    {
        $utc = new \DateTimeZone('UTC');
        $sent = $sent->setTimezone($utc);
        $started = $started->setTimezone($utc);
        $current = $current->setTimezone($utc);

        return $sent >= $started
            && $sent <= $started->modify('+2 minutes')
            && $sent <= $current->modify('+1 minute');
    }
}
