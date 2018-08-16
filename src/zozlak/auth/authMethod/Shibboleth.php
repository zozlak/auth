<?php

/*
 * The MIT License
 *
 * Copyright 2018 zozlak.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace zozlak\auth\authMethod;

use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Shibboleth authentication provider.
 * 
 * Basically it extends the TrustedHeader class with a redirection to
 * a Shibboleth auth endpoint if user is not logged in.
 * 
 * If you prefer "soft" behaviour (if user is not logged in simply skip and try 
 * a next auth method in the chain), please use the TrustedHeader class instead.
 * @author zozlak
 */
class Shibboleth extends TrustedHeader {

    private $authUrl;

    /**
     * Sets up the authentication provider.
     * 
     * @param string $userHeader HTTP header storing user login (e.g. HTTP_EPPN)
     * @param string $headersPrefix name prefix of HTTP headers storing user
     *   data (e.g. HTTP_SHIB_)
     * @param array $headersList explicit list of HTTP header names storing user
     *   data
     * @param string $authUrl Shibboleth login endpoint URL (typically 
     *   https://domain/Shibboleth.sso/Login)
     * @param string $target URL user should be redirected to after successful
     *   login (if not specified current request URL is assumed)
     * @param string $entityId optional Service Provider's entity ID (if not
     *   specified Shibboleth's login endpoint default will be used)
     */
    public function __construct(string $userHeader,
                                string $headersPrefix = null,
                                array $headersList = [], string $authUrl,
                                string $target = null, string $entityId = null) {
        parent::__construct($userHeader, $headersPrefix, $headersList);

        $target        = $target ?? $this->getRequestUrl();
        $this->authUrl = sprintf('%s?target=%s', $authUrl, rawurlencode($target));
        if ($entityId) {
            $this->authUrl .= '&entityID=' . rawurlencode($entityId);
        }
    }

    public function authenticate(UsersDbInterface $db): bool {
        return parent::authenticate($db);
    }

    /**
     * Tries to reconstruct an original request URL.
     * 
     * Will not work properly when the request was proxied to a different path
     * (all paths but the one on last hop are lost).
     * @return string
     */
    private function getRequestUrl(): string {
        $ssl      = filter_input(\INPUT_SERVER, 'HTTPS') === 'on';
        $sp       = strtolower(filter_input(\INPUT_SERVER, 'SERVER_PROTOCOL'));
        $protocol = substr($sp, 0, strpos($sp, '/')) . (($ssl) ? 's' : '' );

        $port = filter_input(\INPUT_SERVER, 'SERVER_PORT');
        $port = ((!$ssl && $port === '80') || ($ssl && $port === '443')) ? '' : ':' . $port;

        $xhost = trim(explode(',', filter_input(\INPUT_SERVER, 'HTTP_X_FORWARDED_HOST'))[0]);
        $host  = filter_input(\INPUT_SERVER, 'HTTP_HOST');
        $sn    = filter_input(\INPUT_SERVER, 'SERVER_NAME');
        $host  = ($xhost ?? $host) ?? $sn;

        return $protocol . '://' . $host . $port . $s['REQUEST_URI'];
    }

    public function advertise(bool $onFailure): bool {
        $cookie = false;
        foreach (array_keys($_COOKIE) as $i) {
            if (substr($i, 0, 13) === '_shibsession_') {
                $cookie = true;
                break;
            }
        }
        if (!$cookie || $onFailure) {
            header('Location: ' . $this->authUrl);
            return true;
        }return false;
    }

}
