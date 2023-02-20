# Hyve-JWT

## Installation
`composer require wg-hyve/hyve-jwt`

`php artisan jwt:generate-keys`

## Usage

Get Pub Key:
```php
use HyveJWT\Generate;

$provider = Generate::provider('eddsa');

return [
    'kid' =>  $provider->getKeyID(),
    'use' =>  $provider->getUse(),
    'kty' =>  $provider->getAlgorithmFamily(),
    'alg' =>  $provider->getAlgorithm(),
    'crv' =>  $provider->getCurve(),
    'x' =>  $provider->getPublicKey()
];
```

Decode:
```php
use HyveJWT\Generate;

$decode = Generate::provider('eddsa')->decode($token);
```

Encode:
```php
use HyveJWT\Generate;

$decode = Generate::provider('eddsa')->jwt($payload);
```