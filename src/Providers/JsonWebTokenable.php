<?php

namespace HyveJWT\Providers;

use stdClass;

interface JsonWebTokenable
{
    public function getPrivateKey(): string;
    public function getPublicKey(): string;
    public function generateKeys(): void;
    public function jwt(array $payload = []): string;
    public function decode(string $token): stdClass;
    public function getAlgorithm(): string;
    public function getAlgorithmFamily(): string;
    public function getCurve(): string;
    public function getUse(): string;
    public function getKeyID(): string;
}
