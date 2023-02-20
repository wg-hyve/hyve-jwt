<?php

namespace HyveJWT\Providers;

use HyveJWT\Exceptions\HyveInvalidAlgoritmException;
use HyveJWT\Exceptions\HyveInvalidCurveException;
use HyveJWT\Exceptions\HyveMissingKeyException;
use App\Helpers\Uuid\Uuid;
use App\Models\CustomerPrefill;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;

class Eddsa implements JwtProviderable
{
    const KEY_ALGORITHM = 'EdDSA';
    const KEY_CURVE = 'Ed25519';

    protected mixed $decodedToken;
    protected string $key;

    private Authenticatable $user;

    /**
     * @throws HyveMissingKeyException
     * @throws HyveInvalidAlgoritmException
     * @throws HyveInvalidCurveException
     */
    private function __construct()
    {
        $reference = config('jwt.providers.kupo.reference_key');
        $token = str_replace('Bearer ', '', request()->header('Authorization'));
        $this->loadPublicKey();

        $this->decodedToken = JWT::decode($token, new Key($this->key, self::KEY_ALGORITHM));

        $this->user = CustomerPrefill::create(
            array_merge(
                [
                    'uuid' => Uuid::v4(),
                    'customer_number' => $this->decodedToken->{$reference},
                    'invalid_at' => now()->addSeconds(config('user.prefill.ttl')),
                ],
                app()->environment(['local', 'development', 'staging']) === true ? ['token' => $token] : [],
            )
        );

        Auth::login($this->user);
    }

    public static function load(): self
    {
        return new self();
    }

    public function validate(): bool
    {
        return $this->user->exists;
    }

    /**
     * @throws HyveInvalidAlgoritmException
     * @throws HyveInvalidCurveException
     * @throws HyveMissingKeyException
     */
    private function loadPublicKey(): void
    {
        $generator = Generators\Eddsa::load();

        if($generator::KEY_ALGORITHM !== self::KEY_ALGORITHM) {
            throw new HyveInvalidAlgoritmException(sprintf('Algorithm %s not supported', Arr::get($data, 'alg')));
        }

        if($generator::KEY_CURVE !== self::KEY_CURVE) {
            throw new HyveInvalidCurveException(sprintf('Curve %s not supported', Arr::get($data, 'alg')));
        }

        $this->key = $generator->getPublicKey();
    }
}
