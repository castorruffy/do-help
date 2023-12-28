<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;

function auth_check(array $event, string $method, array $roles=null): array
{
    //method part
    if ($event['__ow_method'] != $method) {
        return [
            "body" => 'Bad method',
            "statusCode" => 405,
            "headers" => ["accept" => "Content-Type: text/plain"]
        ];
    }

    //jwt part
    $authorizationHeader = $event['__ow_headers']['authorization'] ?? '';
    $parts = explode(' ', $authorizationHeader);

    if (count($parts) !== 2 or $parts[0] !== 'Bearer') {
        return [
            "body" => [
                "message" => "Invalid or missing Bearer token",
            ],
            "statusCode" => 401
        ];
    }

    try {
        $jwt = JWT::decode($parts[1], new Key(getenv('JWT-SECRET'), 'HS256'));

        return [
            "body" => $jwt
            ,
            "statusCode" => 200
        ];
    } catch (ExpiredException $e) {
        return [
            "body" => 'Token expired',
            "statusCode" => 401
        ];
    } catch (SignatureInvalidException $e) {
        return [
            "body" => 'Invalid token signature',
            "statusCode" => 401
        ];
    } catch (BeforeValidException $e) {
        return [
            "body" => 'Token not valid yet',
            "statusCode" => 401
        ];
    } catch (Exception $e) {
        return [
            "body" => 'Invalid token',
            "statusCode" => 401
        ];
    }

    //roles part
}
