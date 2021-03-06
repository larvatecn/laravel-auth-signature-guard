<?php
/**
 * This is NOT a freeware, use is subject to license terms
 * @copyright Copyright (c) 2010-2099 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larva.com.cn/
 * @license http://www.larva.com.cn/license/
 */

class SignatureUtils
{
    public function main()
    {
        $key = '123465';
        $params = [
            'app_id' => 3,
            'timestamp' => time(),
            'signature_version' => '1.0',
            'signature_method' => 'HMAC-SHA1',
            'signature_nonce' => uniqid()
        ];
        echo $this->getSignature($params, $key);
    }

    /**
     * 前面
     * @param array $params
     * @param string $key
     * @return string
     * @throws Exception
     */
    protected function getSignature(array $params, $key)
    {
        ksort($params);
        $query = http_build_query($params, null, '&', PHP_QUERY_RFC3986);
        $stringToSign = $this->percentEncode($query);

        //签名
        if ($params['signature_method'] == 'HMAC-SHA256') {
            return base64_encode(hash_hmac('sha256', $stringToSign, $key . '&', true));
        } elseif ($params['signature_method'] == 'HMAC-SHA1') {
            return base64_encode(hash_hmac('sha1', $stringToSign, $key . '&', true));
        }
        throw new \Exception('This signature method is not supported.');
    }


    /**
     * @param string $string
     *
     * @return null|string|string[]
     */
    protected function percentEncode($string)
    {
        $result = urlencode($string);
        $result = str_replace(['+', '*'], ['%20', '%2A'], $result);
        $result = preg_replace('/%7E/', '~', $result);
        return $result;
    }
}