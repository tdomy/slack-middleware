<?php

namespace SlackMiddleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface as Middleware;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use SlackMiddleware\Exceptions\InvalidRequestException;

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
     * @throws InvalidRequestException
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
     */
    private function getRequestTimestamp(Request $request): int
    {
        return (int) $request->getHeaderLine(self::TIMESTAMP_HEADER_NAME);
    }

    /**
     * @param Request $request
     * @return string
     */
    private function getSignature(Request $request): string
    {
        return $request->getHeaderLine(self::SIGNATURE_HEADER_NAME);
    }

    /**
     * Verify Request-Timestamp header
     *
     * @param Request $request
     * @throws InvalidRequestException
     */
    private function verifyRequestTimestamp(Request $request): void
    {
        $timestamp = $this->getRequestTimestamp($request);
        $params = $request->getServerParams();

        if (abs($params['REQUEST_TIME'] - $timestamp) > 60 * 5) {
            throw new InvalidRequestException('Request timestamp is invalid.');
        }
    }

    /**
     * Verify Signature header
     *
     * @param Request $request
     * @throws InvalidRequestException
     */
    private function verifySignature(Request $request): void
    {
        $base_string = sprintf("v0:%s:%s", $this->getRequestTimestamp($request), (string) $request->getBody());
        $signature = 'v0=' . hash_hmac('sha256', $base_string, $this->signing_secret);

        if ($signature !== $this->getSignature($request)) {
            throw new InvalidRequestException('Signature is invalid.');
        }
    }
}
