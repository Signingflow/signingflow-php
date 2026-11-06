<?php

declare(strict_types=1);

namespace Signingflow;

final class Client
{
    public Config $config;

    public Files $files;

    public Templates $templates;

    public Envelopes $envelopes;

    public WebhookUrls $webhookUrls;

    public WebhookDeliveries $webhookDeliveries;

    public function __construct(string $apiKey, array $options = [])
    {
        $this->config = new Config($apiKey, $options);
        $sender = new Sender($this->config);
        $this->files = new Files($sender);
        $this->templates = new Templates($sender);
        $this->envelopes = new Envelopes($sender, $this->files, $this->templates);
        $this->webhookUrls = new WebhookUrls($sender);
        $this->webhookDeliveries = new WebhookDeliveries($sender);
    }
}
