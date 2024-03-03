<?php

declare(strict_types=1);

namespace Monderka\JwtGenerator\Test\Unit;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Monderka\JwtGenerator\WebTokenGenerator;
use PHPUnit\Framework\TestCase;

final class WebTokenGeneratorTest extends TestCase
{
    private WebTokenGenerator $service;
    private array $config = [
        "jwtAlgo" => "RS256",
        "privateKeyPassPhrase" => "123456789",
        "privateKeyPath" => __DIR__ . "/private.pem",
        "publicKeyPath" => __DIR__ . "/public.pem",
        "accessTokenExpiration" => 3600
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new WebTokenGenerator($this->config);
    }

    public function testGenerate(): void
    {
        $token = $this->service->generate(
            "Test Issuer",
            555,
            "test name",
            [ "scope1", "scope2", "scope3" ],
            [
                "add1" => "test1"
            ]
        );
        $this->assertIsString($token);

        $publicKey = JWKFactory::createFromKeyFile(
            $this->config["publicKeyPath"],
            '',
            [ "use" => "sig" ]
        );
        $algoManager = new AlgorithmManager([ new RS256() ]);
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer()
        ]);
        $jwsVerifier = new JWSVerifier($algoManager);
        $headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker(["RS256"])
            ],
            [
                new JWSTokenSupport()
            ]
        );

        $jws = $serializerManager->unserialize($token);
        $headerCheckerManager->check($jws, 0);
        $this->assertTrue(
            $jwsVerifier->verifyWithKey($jws, $publicKey, 0)
        );
        $payload = json_decode($jws->getPayload(), true);
        $claimChecker = new ClaimCheckerManager([
            new IssuedAtChecker(),
            new NotBeforeChecker(),
            new ExpirationTimeChecker(),
            new IssuerChecker([
                "Test Issuer"
            ])
        ]);
        $claimChecker->check($payload);
        $this->assertArrayHasKey("name", $payload);
        $this->assertArrayHasKey("iss", $payload);
        $this->assertArrayHasKey("sub", $payload);
        $this->assertArrayHasKey("scope", $payload);
        $this->assertArrayHasKey("add1", $payload);
        $this->assertEquals("test name", $payload["name"]);
        $this->assertEquals("Test Issuer", $payload["iss"]);
        $this->assertEquals(555, $payload["sub"]);
        $this->assertEquals("test1", $payload["add1"]);
        $scopes = explode(" ", $payload["scope"]);
        $this->assertEquals(
            [ "scope1", "scope2", "scope3" ],
            $scopes
        );
    }
}
