<?php

namespace HyveJWT\Providers\Generators;

use HyveJWT\Exceptions\HyveMissingKeyException;
use App\Helpers\Uuid\Uuid;
use App\Services\JWT\Providers\JsonWebTokenable;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Storage;
use SodiumException;
use stdClass;

class Eddsa implements JsonWebTokenable
{
    const KEY_ALGORITHM = 'EdDSA';
    const KEY_ALGORITHM_FAMILY = 'OKP';
    const KEY_CURVE = 'Ed25519';
    const USE = 'sig';
    protected string $privatePattern = 'jwt-private.key';
    protected string $publicPattern = 'jwt-public.key';

    public static function load(): self
    {
        return new self();
    }

    private function __construct()
    {
    }

    /**
     * @throws HyveMissingKeyException
     */
    public function getPrivateKey(): string
    {
        if($key = Storage::disk('private')->get($this->privatePattern)) {
            return $key;
        }

        throw new HyveMissingKeyException(sprintf('Private key %s not found', $this->privatePattern));
    }

    /**
     * @throws HyveMissingKeyException
     */
    public function getPublicKey(): string
    {
        if($key = Storage::disk('private')->get($this->publicPattern)) {
            return $key;
        }

        throw new HyveMissingKeyException(sprintf('Private key %s not found', $this->publicPattern));
    }

    /**
     * @throws SodiumException
     */
    public function generateKeys(): void
    {
        $keyPair = sodium_crypto_sign_keypair();

        Storage::disk('private')->put($this->privatePattern, base64_encode(sodium_crypto_sign_secretkey($keyPair)));
        Storage::disk('private')->put($this->publicPattern, base64_encode(sodium_crypto_sign_publickey($keyPair)));
    }

    /**
     * @throws HyveMissingKeyException
     */
    public function jwt(array $payload = []): string
    {
        $payload = array_merge(
            [
                'iss' => config('jwt.create.issuer'),
                'aud' => config('jwt.create.audience'),
                'sub' => config('jwt.create.subject'),
            ],
            $payload,
            [
                'exp' => now()->addSeconds(config('jwt.create.ttl'))->timestamp,
                'iat' => now()->timestamp,
            ]
        );

        return JWT::encode($payload, $this->getPrivateKey(), self::KEY_ALGORITHM);
    }

    /**
     * @throws HyveMissingKeyException
     */
    public function decode(string $token): stdClass
    {
        return JWT::decode($token, new Key($this->getPublicKey(), self::KEY_ALGORITHM));
    }

    public function getAlgorithm(): string
    {
        return self::KEY_ALGORITHM;
    }

    public function getCurve(): string
    {
        return self::KEY_CURVE;
    }

    public function getAlgorithmFamily(): string
    {
        return self::KEY_ALGORITHM_FAMILY;
    }

    public function getUse(): string
    {
        return self::USE;
    }

    /**
     * @throws HyveMissingKeyException
     */
    public function getKeyID(): string
    {
        return Uuid::v5($this->getPublicKey());
    }
}
