<?php

use Firebase\JWT\JWT;
include 'const.php';
require_once('../../vendor/autoload.php');

/** for APACHE
 * 
 * RewriteEngine On
 * RewriteCond %{HTTP:Authorization} ^(.+)$
 * RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
 * 
 */

function getAuthorizationHeader()
{
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER["Authorization"]);
    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
        $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        //print_r($requestHeaders);
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    return $headers;
}


$header = getAuthorizationHeader();

if (!preg_match('/Bearer\s(\S+)/', $header, $matches)) {
    header('HTTP/1.0 400 Bad Request');
    echo 'Token not found in request';
    exit;
}

$jwt = $matches[1];
if (!$jwt) {
    // No token was able to be extracted from the authorization header
    header('HTTP/1.0 400 Bad Request');
    exit;
}

try {
    JWT::$leeway = 60;
    $token = JWT::decode($jwt, $secretKey, ['HS512']);

    $now = new DateTimeImmutable();
    $serverName = $serverURL;

    if (
        $token->iss !== $serverName ||
        $token->nbf > $now->getTimestamp() ||
        $token->exp < $now->getTimestamp()
    ) {
        header('HTTP/1.1 401 Unauthorized');
        exit;
    }
} catch (\Throwable $th) {
    //throw $th;
    header('HTTP/1.1 401 Unauthorized');
    exit;
}
 
// Show the page
