<?php
/**
 * This is NOT a freeware, use is subject to license terms
 * @copyright Copyright (c) 2010-2099 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larva.com.cn/
 * @license http://www.larva.com.cn/license/
 */

namespace Larva\Auth;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\ClientRepository;

/**
 * Class AuthServiceProvider
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class AuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        Auth::extend('signature', function ($app, $name, array $config) {
            return new RequestGuard(function ($request) use ($config) {
                return (new SignatureGuard(
                    Auth::createUserProvider($config['provider']),
                    $this->app->make(ClientRepository::class)
                ))->user($request);
            }, $this->app['request']);
        });
    }
}