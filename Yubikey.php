<?php
/**
 * Class for verifying Yubikey One-Time-Passcodes
 * Validation Protocol Version 2.0
 *
 * @author      Benjamin Cremer <crem0r@gmail.com>
 * @copyright   2013 Benjamin Cremer
 * @license     http://opensource.org/licenses/bsd-license.php New BSD License
 * @link        http://www.yubico.com/
 */
class Yubikey
{
    /**
     * @var array
     */
    protected $_statusMessages = array(
        'OK'                    => 'The OTP is valid.',
        'BAD_OTP'               => 'The OTP is invalid format.',
        'REPLAYED_OTP'          => 'The OTP has already been seen by the service.',
        'BAD_SIGNATURE'         => 'The HMAC signature verification failed.',
        'MISSING_PARAMETER'     => 'The request lacks a parameter.',
        'NO_SUCH_CLIENT'        => 'The request id does not exist.',
        'OPERATION_NOT_ALLOWED' => 'The request id is not allowed to verify OTPs.',
        'BACKEND_ERROR'         => 'Unexpected error in our server. Please contact us if you see this error.',
        'NOT_ENOUGH_ANSWERS'    => 'Server could not get requested number of syncs during before timeout',
        'REPLAYED_REQUEST'      => 'Server has seen the OTP/Nonce combination before',
    );

    /**
     * URL part of validation server
     * @var array
     */
    protected $_urlList = array(
        'api.yubico.com/wsapi/2.0/verify',
        'api2.yubico.com/wsapi/2.0/verify',
        'api3.yubico.com/wsapi/2.0/verify',
        'api4.yubico.com/wsapi/2.0/verify',
        'api5.yubico.com/wsapi/2.0/verify',
    );

    /**
     * @var integer
     */
    protected $_id;

    /**
     * @var string
     */
    protected $_signatureKey;

    /**
     * @var string
     */
    protected $_errorMessage;

    /**
     * @var boolean
     */
    protected $_httpsverify;

    /**
     * Sync level in percentage between
     * 0 and 100 or "fast" or "secure".
     *
     * @var integer | string
     */
    protected $_sl;

    /**
     * @var boolean
     */
    protected $_https;

    /**
     * Set true to get timestamp and session information
     * in the response
     *
     * @var boolean
     */
    protected $_useTimestamp;

    /**
     * If true, wait until all
     * servers responds (for debugging)
     *
     * @var boolean
     */
    protected $_waitForAll;

    /**
     * Max number of seconds to wait for responses
     *
     * @var integer
     */
    protected $_timeout;

    /**
     * @var string
     */
    protected $_currentNonce;

    /**
     * @var string
     */
    protected $_currentOtp;

    /**
     * @param integer $id
     * @param string  $signatureKey
     */
    public function __construct($id, $signatureKey = null)
    {
        $this->_id = $id;
        $this->_signatureKey = base64_decode($signatureKey);

        // Set defaults
        $this->_timeout     = 20;
        $this->_timestamp   = false;
        $this->_https       = true;
        $this->_httpsverify = true;
        $this->_waitForAll  = false;
    }

    /**
     * @param integer | string $level
     * @return Yubikey
     */
    public function setSyncLevel($level)
    {
        $this->_sl = $level;

        return $this;
    }

    /**
     * @return integer | string
     */
    public function getSyncLevel()
    {
        return $this->_sl;
    }

    /**
     * @param boolean $https
     * @return Yubikey
     */
    public function setHttps($https = true)
    {
        $this->_https = $https;

        return $this;
    }

    /**
     * @return boolean
     */
    public function getHttps()
    {
        return $this->_https;
    }

    /**
     * @param boolean $verify
     * @return Yubikey
     */
    public function setVerifyHttps($verify = true)
    {
        $this->_httpsverify = $verify;

        return $this;
    }

    /**
     * @return boolean
     */
    public function getVerifyHttps()
    {
        return $this->_https;
    }

    /**
     * Specify to use different URL parts for verification without scheme
     *
     * @param array $urlList
     * @return Yubikey
     */
    public function setValidationUrls($urlList)
    {
        $this->_urlList = $urlList;

        return $this;
    }

    /**
     * Get URL parts to use for validation.
     *
     * @return array Server URL parts
     */
    public function getValidationUrls()
    {
        return $this->_urlList;
    }

    /**
     * @param boolean $waitForAll
     * @return Yubikey
     */
    public function setWaitForAll($waitForAll = true)
    {
        $this->_waitForAll = $waitForAll;

        return $this;
    }

    /**
     * @return boolean
     */
    public function getWaitForAll()
    {
        return $this->_waitForAll;
    }

    /**
     * @param integer $int
     * @return Yubikey
     */
    public function setTimeout($int)
    {
        $this->_timeout = $int;

        return $this;
    }

    /**
     * @return integer
     */
    public function getTimeout()
    {
        return $this->_timeout;
    }

    /**
     * @param boolean $useTimestamp
     * @return Yubikey
     */
    public function setUseTimestamp($useTimestamp = true)
    {
        $this->_useTimestamp = $useTimestamp;

        return $this;
    }

    /**
     * @return boolean
     */
    public function getUseTimestamp()
    {
        return $this->_useTimestamp;
    }

    /**
     * @param string $otp
     * @return boolean
     */
    public function verify($otp)
    {
        $otp = strtolower($otp);

        if (!$this->_otpIsModhex($otp)) {
            $this->_errorMessage = 'OTP NOT MODHEX';

            return false;
        }

        $this->_currentNonce = $this->_generateNonce();
        $this->_currentOtp   = $otp;
        $this->_errorMessage = null;
        $isReplayed          = false;
        $isValid             = false;
        $hasResult           = false;
        $result              = array();

        $queries = $this->_getQueries();

        $curlHandles = array();
        $curlMultiHandle = curl_multi_init();

        foreach ($queries as $query) {
            $curlHandle = curl_init($query);
            curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, true);

            if (!$this->_httpsverify) {
                curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, false);
            }

            curl_setopt($curlHandle, CURLOPT_FAILONERROR, true);

            // If timeout is set, we better apply it here as well
            // in case the validation server fails to follow it.
            if ($this->_timeout) {
                curl_setopt($curlHandle, CURLOPT_TIMEOUT, $this->_timeout);
                curl_setopt($curlHandle, CURLOPT_CONNECTTIMEOUT, $this->_timeout);
            }

            curl_multi_add_handle($curlMultiHandle, $curlHandle);
            $curlHandles[] = $curlHandle;
        }

        $curlMultiIsRunning = false;
        do {
            while (($execReturnValue = curl_multi_exec($curlMultiHandle, $curlMultiIsRunning)) == CURLM_CALL_MULTI_PERFORM);

            if ($execReturnValue != CURLM_OK) {
                break;
            }

            while ($curlMultiHandleInfo = curl_multi_info_read($curlMultiHandle)) {
                if ($curlMultiHandleInfo['result'] != CURLE_OK) {
                    continue;
                }

                $info = curl_getinfo($curlMultiHandleInfo['handle']);

                if ($info['http_code'] != 200) {
                    continue;
                }

                $output = curl_multi_getcontent($curlMultiHandleInfo['handle']);

                $result = $this->_processOutput($output);
                if (($result['isValid'] || $result['isReplayed'])) {
                    $isValid    = $result['isValid'];
                    $isReplayed = $result['isReplayed'];
                    $hasResult  = true;
                }
            }
        } while ($curlMultiIsRunning && (!$hasResult || $this->_waitForAll));

        // Cleanup open handles
        foreach ($curlHandles as $curlHandle) {
            curl_multi_remove_handle($curlMultiHandle, $curlHandle);
            curl_close($curlHandle);
        }
        curl_multi_close($curlMultiHandle);

        if ($isReplayed) {
            $this->_errorMessage =  'REPLAYED_OTP';

            return false;
        }

        if ($isValid) {
            return true;
        }

        $this->_errorMessage = 'NO_VALID_ANSWER: ' . $result['message'];

        return false;
    }

    /**
     * Returns response message from verification attempt.
     *
     * @return string
     */
    public function getErrorMessage()
    {
        return $this->_errorMessage;
    }

    /**
     * @return array
     */
    protected function _getQueries()
    {
        $params = array(
            'id'    => $this->_id,
            'otp'   => $this->_currentOtp,
            'nonce' => $this->_currentNonce,
        );

        if (isset($this->_sl)) {
            $params['sl'] = $this->_sl;
        }

        if ($this->_useTimestamp) {
            $params['timestamp'] = 1;
        }

        if (isset($this->_timeout)) {
            $params['timeout'] = $this->_timeout;
        }

        $queryString = $this->_buildQuery($params);

        if ($this->_signatureKey) {
            $queryString .= '&h=' . urlencode($this->_createSignature($queryString));
        }

        if ($this->_https) {
            $scheme = 'https://';
        } else {
            $scheme = 'http://';
        }

        $queries = array();

        foreach ($this->_urlList as $url) {
            $queries[] = $scheme. $url . '?' . $queryString;
        }

        return $queries;
    }

    /**
     * @param string $output
     * @return array
     */
    protected function _processOutput($output)
    {
        $result = array(
            'message'    => '',
            'isValid'    => false,
            'isReplayed' => false,
        );

        $out = array();
        if (!preg_match('/status=([a-zA-Z0-9_]+)/', $output, $out)) {
            $result['message'] = 'Missing status code, malformed response?';

            return $result;
        }
        $status = $out[1];

        $response = $this->_parseResponse($output);

        // These errors are typically the administator's fault
        if (
            $status == 'MISSING_PARAMETER' ||
            $status == 'NO_SUCH_CLIENT' ||
            $status == 'BAD_SIGNATURE' ||
            $status == 'OPERATION_NOT_ALLOWED'
) {
            $result['message'] = $this->_statusMessages[$status];

            return $result;
        }

        // At this point the server has accepted and validated the request.
        // Let's check if the server response matches our request
        if (!$this->_checkOtpNonceMatch($response)) {
            $result['message'] = 'OTP and/or Nonce does not match request';

            return $result;
        }

        if ($this->_signatureKey && !$this->_checkResponseSignature($response)) {
            $result['message'] = 'Bad Response Signature';

            return $result;
        }

        // At this point we can be sure that the server responded to our request
        // so we can evaluate the response
        if ($status == 'REPLAYED_OTP') {
            $result['message']    = $this->_statusMessages[$status];
            $result['isReplayed'] = true;

            return $result;
        }

        if ($status == 'OK') {
            $result['message'] = $this->_statusMessages[$status];
            $result['isValid'] = true;

            return $result;
        }

        if (array_key_exists($status, $this->_statusMessages)) {
            $result['message'] = $this->_statusMessages[$status];

            return $result;
        }

        // hue? This should not happen
        $result['message'] = 'Unknown status: ' . $status;

        return $result;
    }

    /**
     * @param string $queryString
     * @return string
     */
    protected function _createSignature($queryString)
    {
        return base64_encode(hash_hmac('sha1', $queryString, $this->_signatureKey, true));
    }

    /**
     * @param array $result
     * @return boolean
     */
    protected function _checkOtpNonceMatch($result)
    {
        return ($result['otp'] == $this->_currentOtp  && $result['nonce'] == $this->_currentNonce);
    }

    /**
     * @param array $response
     * @return boolean
     */
    protected function _checkResponseSignature($response)
    {
        $responseSignature = $response['h'];
        unset($response['h']);

        $queryString = $this->_buildQuery($response);
        $signature = $this->_createSignature($queryString);

        return ($responseSignature == $signature);
    }

    /**
     * @param array $parts
     * @return string
     */
    protected function _buildQuery($parts)
    {
        ksort($parts);

        $queryString = '';
        foreach ($parts as $p => $v) {
            $queryString .= '&' . $p . '=' . $v;
        }

        return ltrim($queryString, '&');
    }

    /**
     * @param string $otp
     * @return boolean
     */
    protected function _otpIsModhex($otp)
    {
        return (preg_match('/^[cbdefghijklnrtuv]{32,48}$/', $otp));
    }

    /**
     * @todo use better algorithm to create nonce (openssl_random_pseudo_bytes)
     * @return string
     */
    protected function _generateNonce()
    {
        return md5(uniqid(mt_rand(), true));
    }

    /**
     * @param string $response
     * @return array
     */
    protected function _parseResponse($response)
    {
        $result = array();

        $response = explode("\n", $response);

        $parameters = array(
            'h',
            'nonce',
            'otp',
            'sessioncounter',
            'sessionuse',
            'sl',
            'status',
            't',
            'timeout',
            'timestamp'
        );

        foreach ($response as $row) {
            foreach ($parameters as $param) {
                if (substr($row, 0, strlen($param) + 1) == $param  . '=') {
                    $result[$param] = substr(trim($row), strlen($param) + 1);
                }
            }
        }

        return $result;
    }
}
