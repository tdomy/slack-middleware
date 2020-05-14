<?php

namespace Tdomy\Slack\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface as Middleware;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

class Verification implements Middleware
{
    private const TIMESTAMP_HEADER_NAME = 'X-Slack-Request-Timestamp';
    private const SIGNATURE_HEADER_NAME = 'X-Slack-Signature';

    /**
     * @var string $signing_secret
     */
    private $signing_secret;

    /**
     * @param string $signing_secret
     */
    public function __construct(string $signing_secret)
    {
        $this->signing_secret = $signing_secret;
    }

    /**
     * {@inheritdoc}
     */
    public function process(Request $request, RequestHandler $handler): Response
    {
        $this->verifyRequestTimestamp($request);

        $this->verifySignature($request);

        return $handler->handle($request);
    }

    /**
     * @param Request $request
     * @return int
     * @throws \Exception
     */
    private function getRequestTimestamp(Request $request): int
    {
        return (int) $request->getHeaderLine(self::TIMESTAMP_HEADER_NAME);
    }

    /**
     * @param Request $request
     * @return string
     * @throws \Exception
     */
    private function getSignature(Request $request): string
    {
        return $request->getHeaderLine(self::SIGNATURE_HEADER_NAME);
    }

    /**
     * Verify Request-Timestamp header
     *
     * @param Request $request
     * @throws \Exception
     */
    private function verifyRequestTimestamp(Request $request): void
    {
        $timestamp = $this->getRequestTimestamp($request);
        $params = $request->getServerParams();

        if (abs($params['REQUEST_TIME'] - $timestamp) > 60 * 5) {
            throw new \Exception('Request timestamp is invalid.');
        }
    }

    /**
     * Verify Signature header
     *
     * @param Request $request
     * @throws \Exception
     */
    private function verifySignature(Request $request): void
    {
        $base_string = sprintf("v0:%s:%s", $this->getRequestTimestamp($request), (string) $request->getBody());
        $signature = 'v0=' . hash_hmac('sha256', $base_string, $this->signing_secret);

        if ($signature !== $this->getSignature($request)) {
            throw new \Exception('Signature is invalid.');
        }
    }
}
