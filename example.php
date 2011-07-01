<?php
// Generate your api id and signature key
// at https://api.yubico.com/get-api-key/

$apiId = 0000;
$signatureKey = 'signatureKey';

if (!isset($_SERVER['argv'][1])) {
    echo "\n OTP not set \n";
    echo "\nUsage: php example.php otp";
    echo "\nEg. php example.php ccbbddeertkrctjkkcglfndnlihhnvekchkcctif \n\n";
    exit;
}

$otp = strtolower($_SERVER['argv'][1]);

require 'Yubikey.php';

$yubikey = new Yubikey($apiId, $signatureKey);
if ($yubikey->verify($otp)) {
echo "	PASS";
} else {
    echo "FAILED";
    echo "\nResponse: " . $yubikey->getErrorMessage() . "\n";
}
