<?php 
    declare(strict_types=1);
    use Firebase\JWT\JWT;
    include 'const.php';
    require_once('./vendor/autoload.php');


    // Get input data
    $username_input = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $password_input = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $userGroupId = '1';


    // Get hash from database
    // $str = file_get_contents("../../user.json");
    // $json = json_decode($str, true); // decode the JSON into an associative array
    // for ($i=0; $i < sizeof($json['accounts']); $i++) { 
    //     // echo $json['accounts'][$i]['username'];
    //     // echo $json['accounts'][$i]['password'];
    //     if ($username_input === $json['accounts'][$i]['username']) { // Check user
    //         $hash = $json['accounts'][$i]['password'];
    //     }
    // }


    // Verify password & hash
    $hasValidCredentials = password_verify($password_input, $hash);


    // Create JWT
    if ($hasValidCredentials) {
        $tokenId    = base64_encode(random_bytes(16));
        $issuedAt   = new DateTimeImmutable();
        $expire     = $issuedAt->modify('+2 hours')->getTimestamp();      // Add 60 seconds
        $serverName = $serverURL;
        $username   = $username_input;                                           // Retrieved from filtered POST data
    
        // Create the token as an array
        $data = [
            'iat'  => $issuedAt->getTimestamp(),    // Issued at: time when the token was generated
            'jti'  => $tokenId,                     // Json Token Id: an unique identifier for the token
            'iss'  => $serverName,                  // Issuer
            'nbf'  => $issuedAt->getTimestamp(),    // Not before
            'exp'  => $expire,                      // Expire
            'data' => [                             // Data related to the signer user
                'user' => $username,            // User name
                'roles' => 'admins',
                'userGroup' => $userGroupId
            ]
        ];
    
        // Encode the array to a JWT string.
        echo JWT::encode(
            $data,      //Data to be encoded in the JWT
            $secretKey, // The signing key
            'HS512'     // Algorithm used to sign the token, see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3
        );
    }
    
?>