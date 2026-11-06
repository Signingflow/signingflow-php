<?php

declare(strict_types=1);

namespace Signingflow;

final class Files
{
    private const MAX_BYTES = 25 * 1024 * 1024;

    private const MIME = [
        'pdf' => 'application/pdf',
        'png' => 'image/png',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'txt' => 'text/plain',
        'json' => 'application/json',
    ];

    public function __construct(private Sender $sender)
    {
    }

    public function create(array $params = []): StoredFile
    {
        $loaded = $this->load($params);
        $added = $this->sender->call(
            'StorageService_BatchAddStorage',
            body: [
                'storages' => [[
                    'originalName' => $loaded['filename'],
                    'displayName' => $loaded['filename'],
                    'size' => (string) strlen($loaded['data']),
                    'extension' => $loaded['extension'],
                    'mimeType' => $loaded['mime'],
                ]],
            ],
            idempotencyKey: (string) ($params['idempotency_key'] ?? ''),
        );
        $found = Models::findStorage($added);
        if ($found === null) {
            throw new APIError('Storage did not return an upload URL.');
        }
        [$name, $fileId, $rawUrl] = $found;
        $upload = Path::allowedUploadUrl($rawUrl, $this->sender->config->uploadHosts);
        $this->sender->putBytes($upload, $loaded['mime'], $loaded['data']);
        $this->sender->call('StorageService_BatchAcknowledgeUpload', body: ['names' => [$name]]);

        return new StoredFile($name, $fileId);
    }

    /** @return array{data: string, filename: string, extension: string, mime: string} */
    private function load(array $params): array
    {
        $hasFile = array_key_exists('file', $params) && $params['file'] !== null;
        $path = trim((string) ($params['path'] ?? ''));
        $hasPath = $path !== '';
        if ($hasFile && $hasPath) {
            throw new InvalidRequestError('Pass file bytes or a path, not both.');
        }
        if (!$hasFile && !$hasPath) {
            throw new InvalidRequestError('Pass file bytes or a path.');
        }
        if ($hasFile) {
            if (!is_string($params['file'])) {
                throw new InvalidRequestError('Pass file bytes or a path.');
            }
            $data = $params['file'];
        } else {
            $data = Jail::read($this->sender->config->uploadRoot, $path);
        }
        if (strlen($data) > self::MAX_BYTES) {
            throw new InvalidRequestError('The file is larger than 25 MB.');
        }
        $filename = trim((string) ($params['filename'] ?? ''));
        if ($filename === '' && $hasPath) {
            $filename = basename($path);
        }
        if ($filename === '' || $filename === '.' || $filename === '/') {
            throw new InvalidRequestError('filename is required when file is not a path.');
        }
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $mime = trim((string) ($params['mime_type'] ?? ''));
        if ($mime === '') {
            $mime = self::MIME[$extension] ?? '';
        }
        if ($mime === '') {
            $mime = 'application/octet-stream';
        }
        if (Config::badHeader($mime)) {
            throw new InvalidRequestError('invalid header value');
        }

        return ['data' => $data, 'filename' => $filename, 'extension' => $extension, 'mime' => $mime];
    }
}
