<?php

namespace Monderka\JwtGenerator;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Core\Algorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use DateTime;
use JsonException;

final class WebTokenGenerator
{
    private JWSSerializerManager $serializerManager;
    private JWSBuilder $builder;
    private ?JWK $privateKey = null;

    /**
     * @param array{
     *     "jwtAlgo": string,
     *     "privateKeyPassPhrase": string,
     *     "privateKeyPath": string,
     *     "accessTokenExpiration": int
     * } $config
     */
    public function __construct(
        private readonly array $config
    ) {
        $algo = $this->createAlgorithm($this->config["jwtAlgo"]);
        $algoManager = new AlgorithmManager([ $algo ]);
        $this->builder = new JWSBuilder($algoManager);

        $this->serializerManager = new JWSSerializerManager([
            new CompactSerializer()
        ]);
    }

    private function createAlgorithm(string $algoName): Algorithm
    {
        $class = match ($algoName) {
            "EdDSA" => EdDSA::class,
            "ES256" => ES256::class,
            "ES384" => ES384::class,
            "ES512" => ES512::class,
            "HS256" => HS256::class,
            "HS384" => HS384::class,
            "HS512" => HS512::class,
            "PS256" => PS256::class,
            "PS384" => PS384::class,
            "PS512" => PS512::class,
            "RS256" => RS256::class,
            "RS384" => RS384::class,
            "RS512" => RS512::class,
            default => None::class
        };
        return new $class();
    }

    private function getPrivateKey(): JWK
    {
        if (empty($this->privateKey)) {
            $this->privateKey = JWKFactory::createFromKeyFile(
                $this->config["privateKeyPath"],
                $this->config["privateKeyPassPhrase"] ?? '',
                [ "use" => "sig" ]
            );
        }
        return $this->privateKey;
    }

    /**
     * @param string $jwtIssuer
     * @param string|int $userId
     * @param string|null $name
     * @param array<int, string> $scopes
     * @param array<string, scalar> $opts
     * @return string
     * @throws JsonException
     */
    public function generate(
        string $jwtIssuer,
        string|int $userId,
        ?string $name = null,
        array $scopes = [],
        array $opts = []
    ): string {
        $time = (new DateTime())->getTimestamp();
        $payload = [
            'iss' => $jwtIssuer,
            'sub' => (string) $userId,
            'exp' => $time + (int) $this->config["accessTokenExpiration"],
            'iat' => $time,
            'nbf' => $time,
            'alg' => $this->config["jwtAlgo"],
            'name' => $name,
            'scope' => implode(" ", $scopes)
        ];
        $jws = $this->builder->create()
            ->withPayload(
                json_encode(
                    array_merge($opts, $payload),
                    JSON_THROW_ON_ERROR
                )
            )
            ->addSignature($this->getPrivateKey(), [ "alg" => $this->config["jwtAlgo"] ])
            ->build();
        return $this->serializerManager->serialize('jws_compact', $jws, 0);
    }
}
