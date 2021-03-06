# laravel-auth-signature-guard

适用于 Laravel Auth 的签名看守器，基于 Laravel Passport

## 安装 

```bash
composer require larva/laravel-auth-signature-guard
```

```php
//认证配置
/config/auth.php

//增加一个看守器

'guards' => [
	'web'=>[],//原WEB的
	'api'=>[],//API
	'signature'=>[//新增的
		'driver'=>'signature'
		'provider'=>'users',
	]
]
// 使用时在控制器中

class SDKController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:signature');
    }
}

//按照以上配置，该控制器所有的方法都会经过签名看守器认证。

```


### 公共请求参数

公共请求参数是每个接口都需要使用到的请求参数。

| 名称 | 类型 | 描述 |
| ------------- | ----------- | ----------- |
| `app_id` | String | 访问服务使用的应用ID。 |
| `timestamp` | Int | 请求的时间戳，10位数整形。 |
| `signature` | String | 签名结果串。 |
| `signature_method` | String | 签名方式，取值：HMAC-SHA1/HMAC-SHA256 |
| `signature_version` | String | 签名版本，取值：1.0 |
| `signature_nonce` | String | 唯一随机数，用于防止网络重放攻击。在不同请求间要使用不同的随机数值。 |




参数签名计算 例子

```php
$appKey = '123456';
$params = [
    'app_id' => 3, 
    'timestamp' => 1555069945,
    'signature_method'=>'HMAC-SHA1',
    'signature_version'=>'1.0',
    'signature_nonce'=>'rakdienakdig',
    'key1'=>'val1',
    'key2'=>'val2'
];

//排序参数
//按照键名对关联数组进行升序排序
ksort($params);
//编码
$stringToSign = urlencode(http_build_query($params, null, '&', PHP_QUERY_RFC3986));
$stringToSign = str_replace(['+', '*'], ['%20', '%2A'], $stringToSign);
$stringToSign = preg_replace('/%7E/', '~', $stringToSign);

//签名
$params['signature'] = base64_encode(hash_hmac('sha1', $stringToSign, $appKey.'&', true));

// 你的HTTP 实例，
$res = $http->post('your api url/path',$params);

//其中参数中的时间戳和世界标准时间相差不能超过1分钟。

//签名计算例子 在tests 目录
```


