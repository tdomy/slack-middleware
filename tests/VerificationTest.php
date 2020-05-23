<?php

namespace TestSlackMiddleware;

use Mockery;
use Mockery\Adapter\Phpunit\MockeryTestCase;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\StreamInterface as Stream;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use SlackMiddleware\Verification;
use SlackMiddleware\Exceptions\InvalidRequestException;

class VerificationTest extends MockeryTestCase
{
    public function testValidRequest()
    {
        $middleware = new Verification('xsecretx');
        $request = $this->createRequest(
            [
                'X-Slack-Request-Timestamp' => '100000',
                'X-Slack-Signature' => 'v0=7ed68a15da6a6083fbb84d0712701aec61b7b5835196bc1c28e71be78f928c09', // 'v0=' . hash_hmac('sha256', 'v0:100000:text=testCase&user=tdomy', 'xsecretx')
            ],
            [
                'REQUEST_TIME' => '100300',
            ],
            'text=testCase&user=tdomy'
        );
        $response = Mockery::mock(Response::class);
        $request_handler = Mockery::mock(RequestHandler::class);
        $request_handler->shouldReceive('handle')
            ->with($request)
            ->once()
            ->andReturn($response);

        $this->assertSame($response, $middleware->process($request, $request_handler));
    }

    public function testInvalidTimestamp()
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Request timestamp is invalid.');

        $middleware = new Verification('xsecretx');
        $request = $this->createRequest(
            [
                'X-Slack-Request-Timestamp' => '100000',
                'X-Slack-Signature' => 'v0=7ed68a15da6a6083fbb84d0712701aec61b7b5835196bc1c28e71be78f928c09', // 'v0=' . hash_hmac('sha256', 'v0:100000:text=testCase&user=tdomy', 'xsecretx')
            ],
            [
                'REQUEST_TIME' => '100301',
            ],
            'text=testCase&user=tdomy'
        );
        $request_handler = Mockery::mock(RequestHandler::class);
        $request_handler->shouldNotReceive('handle');

        $middleware->process($request, $request_handler);
    }

    public function testInvalidSignature()
    {
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Signature is invalid.');

        $middleware = new Verification('xsecretx');
        $request = $this->createRequest(
            [
                'X-Slack-Request-Timestamp' => '100000',
                'X-Slack-Signature' => 'v0=7ed68a15da6a6083fbb84d0712701aec61b7b5835196bc1c28e71be78f928c08',
            ],
            [
                'REQUEST_TIME' => '100300',
            ],
            'text=testCase&user=tdomy'
        );
        $request_handler = Mockery::mock(RequestHandler::class);
        $request_handler->shouldNotReceive('handle');

        $middleware->process($request, $request_handler);
    }

    private function createRequest(array $headers, array $server_params, string $body)
    {
        $request = Mockery::mock(Request::class);

        foreach ($headers as $header => $value) {
            $request->shouldReceive('getHeaderLine')
                ->with($header)
                ->andReturn($value);
        }

        $request->shouldReceive('getServerParams')
            ->andReturn($server_params);

        $stream = Mockery::mock(Stream::class);
        $stream->shouldReceive('__toString')
            ->andReturn($body);
        $request->shouldReceive('getBody')
            ->andReturn($stream);

        return $request;
    }
}
