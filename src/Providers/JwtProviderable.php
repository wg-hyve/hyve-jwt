<?php

namespace HyveJWT\Providers;


interface JwtProviderable
{
    public static function load(): self;

    public function validate(): bool;
}
