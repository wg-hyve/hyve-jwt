<?php

namespace HyveJWT;

use HyveJWT\Providers\Generators\Eddsa;
use HyveJWT\Providers\JsonWebTokenable;

class Generate
{
    public static function provider(string $provider): JsonWebTokenable
    {
        return match (strtolower($provider)) {
            'eddsa' => Eddsa::load()
        };
    }
}
