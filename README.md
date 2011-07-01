YubiKey OTP Verification
========================

## Stand-alone PHP class for verifying Yubikey One-Time-Passcodes
### Based on the validation protocol version 2.0.

* Yubico website: http://www.yubico.com
* Yubico documentation: http://www.yubico.com/developers/intro/
* Validation Protocol Version 2.0 FAQ: http://www.yubico.com/developers/version2/
* Validation Protocol Version 2.0 description: http://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20

Compatible with the [Zend Framework Coding Standard](http://framework.zend.com/manual/en/coding-standard.html)

# Usage

Generate your client id and signature key (https://api.yubico.com/get-api-key/)

<pre>
require 'Yubikey.php';

$yubikey = new Yubikey($apiID, $signatureKey);
if ($yubikey->verify($otp)) {
    echo "PASS";
} else {
    echo "FAILED";
    echo "\nResponse: " . $yubikey->getErrorMessage() . "\n";
}
</pre>