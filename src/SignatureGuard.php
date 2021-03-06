<?php
/**
 * This is NOT a freeware, use is subject to license terms
 * @copyright Copyright (c) 2010-2099 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larva.com.cn/
 * @license http://www.larva.com.cn/license/
 */

namespace Larva\Auth;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Laravel\Passport\ClientRepository;

/**
 * Class SignatureGuard
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class SignatureGuard
{
    const SIGNATURE_METHOD_HMACSHA1 = 'HMAC-SHA1';
    const SIGNATURE_METHOD_HMACSHA256 = 'HMAC-SHA256';

    /**
     * The user provider implementation.
     *
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    protected $provider;

    /**
     * The client repository instance.
     *
     * @var \Laravel\Passport\ClientRepository
     */
    protected $clients;

    /**
     * Create a new authentication guard.
     *
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param ClientRepository $clients
     */
    public function __construct(UserProvider $provider, ClientRepository $clients)
    {
        $this->provider = $provider;
        $this->clients = $clients;
    }

    /**
     * 获取传入请求的用户。
     *
     * @param \Illuminate\Http\Request $request
     * @return User|void
     * @throws AuthenticationException
     */
    public function user(Request $request)
    {
        //验证公共请求参数
        if (!$request->has('app_id')) {
            throw new AuthenticationException('Missing app_id parameter.');
        }

        if (!$request->has('timestamp')) {
            throw new AuthenticationException('Missing timestamp parameter.');
        }

        if (!$request->has('signature')) {
            throw new AuthenticationException('Missing signature parameter.');
        }

        if (!$request->has('signature_method')) {
            throw new AuthenticationException('Missing signature_method parameter.');
        }

        if (!$request->has('signature_version')) {
            throw new AuthenticationException('Missing signature_version parameter.');
        }

        if (!$request->has('signature_nonce')) {
            throw new AuthenticationException('Missing signature_nonce parameter.');
        }
        //验证重放攻击
        if (Cache::has(__METHOD__ . $request->input('signature_nonce'))) {
            throw new AuthenticationException('The signature_nonce verification failed.');
        } else {
            Cache::put(__METHOD__ . $request->input('signature_nonce'), 'a', Carbon::now()->addMinutes(1));
        }

        //获取参数
        $params = $request->except(['signature']);

        //检查时间戳，误差1分钟
        if ((time() - intval($params['timestamp'])) > 60) {
            throw new AuthenticationException('Client time is incorrect.');
        }

        //获取有效的 Client
        if (($client = $this->clients->findActive($params['app_id'])) == null) {
            throw new AuthenticationException('App_id is incorrect.');
        }

        if ($params['signature_version'] == '1.0') {
            if ($request->input('signature') == $this->getSignatureV1($params, $client->secret)) {
                return $client->user;
            }
        }
        throw new AuthenticationException('Signature verification failed');
    }

    /**
     * Calculate signature for request
     *
     * @param array $params parameters.
     * @param string $key
     * @return string
     * @throws AuthenticationException
     */
    protected function getSignatureV1(array $params, string $key): string
    {
        //参数排序
        ksort($params);
        $query = http_build_query($params, null, '&', PHP_QUERY_RFC3986);
        $stringToSign = $this->percentEncode($query);
        //签名
        if ($params['signature_method'] == self::SIGNATURE_METHOD_HMACSHA256) {
            return base64_encode(hash_hmac('sha256', $stringToSign, $key . '&', true));
        } elseif ($params['signature_method'] == self::SIGNATURE_METHOD_HMACSHA1) {
            return base64_encode(hash_hmac('sha1', $stringToSign, $key . '&', true));
        } else {
            throw new AuthenticationException('This signature method is not supported.');
        }
    }

    /**
     * @param string $string
     * @return string
     */
    protected function percentEncode(string $string): string
    {
        $result = urlencode($string);
        $result = str_replace(['+', '*'], ['%20', '%2A'], $result);
        $result = preg_replace('/%7E/', '~', $result);
        return $result;
    }
}