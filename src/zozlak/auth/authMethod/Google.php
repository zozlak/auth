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

use BadMethodCallException;
use RuntimeException;
use stdClass;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Feature-reach Google access_token-based authentication provider.
 *
 * Despite prividing access_token-based authentication helps to obtain a
 * token by redirecting to the proper Google API endpoint and is able to refresh
 * expired ones (if they were issued using the 'offline' access type).
 * 
 * Data provided by the getUserData() are all the data returned for the provided 
 * token by the https://www.googleapis.com/oauth2/v3/tokeninfo Google API 
 * endpoint.
 * 
 * You can control amount of data included in tokens generated using this class
 * with the $scope parameter passed to the constructor.
 * 
 * @author zozlak
 */
class Google implements AuthMethodInterface {

    const TOKEN_URL     = 'https://www.googleapis.com/oauth2/v4/token';
    const TOKENINFO_URL = 'https://www.googleapis.com/oauth2/v3/tokeninfo';
    const AUTH_URL      = 'https://accounts.google.com/o/oauth2/auth';
    const CONTENT_TYPE  = ['Content-Type' => 'application/x-www-form-urlencoded'];

    /**
     * Default auth request configuration.
     * 
     * - redirect_uri must match the service config 
     *   (see https://console.developers.google.com/apis/credentials)
     * - for scopes list see see 
     *   https://developers.google.com/identity/protocols/googlescopes#google_sign-in
     * - access_type can be 'online' or 'offline', the latter one allows token refreshing
     * - state can be any value; it's included in the returned redirect URL and 
     *   allows to perform custom redirects on our side or increase security
     * - include_granted_scopes - see 
     *   https://developers.google.com/identity/protocols/OAuth2WebServer#incrementalAuth
     * - login_hint - user email (if known), so only password has to be provided
     * - prompt - which dialogs should be presented (coma-delimited list): 
     *   none, consent, select_account, see https://developers.google.com/identity/protocols/OAuth2WebServer#creatingclient
     * - refresh_time - if a refresh token is available and current token will
     *   expire in less then `refresh_time` seconds, it will be automatically refreshed
     */
    const AUTH_CONFIG = [
        'redirect_uri'           => '',
        'scope'                  => 'email',
        'access_type'            => 'online',
        'state'                  => '',
        'include_granted_scopes' => false,
        'login_hint'             => '',
        'prompt'                 => '',
        'refresh_time'           => 600,
    ];

    /**
     *
     * @var GuzzleHttp\Client
     */
    private $client;

    /**
     * Stores all Google Sign-In API related config
     * @var stdClass
     */
    private $appConfig;
    private $authConfig;
    private $usernameField;
    private $data;

    /**
     * Sets up the authentication provider.
     * 
     * @param string $token access_token (or an empty string if a token is 
     *   missing)
     * @param mixed $appConfig service config as downloaded from 
     *   https://console.developers.google.com/apis/credentials (as array, 
     *   object or JSON file path; if array or object, must contain 'client_id' 
     *   and 'client_secret')
     * @param array $authConfig configuration of an authorization request made
     *   when token is invalid or missing - see the AUTH_CONFIG constant;
     *   if NULL, no redirection to the Google auth service is made when 
     *   a token is missing or invalid
     * @param string $usernameField field to be used as a user name - choose 
     *   according to the chosen scope
     */
    public function __construct(string $token, $appConfig,
                                array $authConfig = null,
                                string $usernameField = 'email') {
        $this->client        = new Client();
        $this->usernameField = $usernameField;

        if (is_string($appConfig) && file_exists($appConfig)) {
            $this->appConfig = json_decode(file_get_contents($appConfig))->web;
        } else {
            $this->appConfig = (object) $appConfig;
        }
        $this->data = (object) ['access_token' => $token];

        if ($authConfig) {
            $this->authConfig                  = array_merge(self::AUTH_CONFIG, $authConfig);
            $this->authConfig['response_type'] = 'code';
            $this->authConfig['client_id']     = $this->appConfig->client_id;
            if (strlen($this->authConfig['redirect_uri']) === 0) {
                if (!isset($this->appConfig->redirect_uris) || !is_array($this->appConfig->redirect_uris) || count($this->appConfig->redirect_uris) === 0) {
                    throw new BadMethodCallException('redirect URI not specified');
                }
                $this->authConfig['redirect_uri'] = $this->appConfig->redirect_uris[0];
            }
            $this->authConfig['include_granted_scopes'] = $this->authConfig['include_granted_scopes'] ? 'true' : 'false';
        }
    }

    public function authenticate(UsersDbInterface $db): bool {
        $code = filter_input(\INPUT_GET, 'code');
        if ($code) {
            try {
                $this->fetchTokenFromCode($code);
            } catch (GuzzleException $ex) {
                
            }
        }
        try {
            $this->fetchData($db);
            return true;
        } catch (GuzzleException $ex) {
            return false;
        }
    }

    public function getUserData(): stdClass {
        return $this->data;
    }

    public function getUserName(): string {
        $field = $this->usernameField;
        return $this->data->$field;
    }

    public function advertise(bool $onFailure): bool {
        if (!$this->authConfig) {
            throw new RuntimeException('Authorization config missing');
        }
        if (!$this->data->access_token || $onFailure) {
            header('Location: ' . $this->getAuthUrl());
            return true;
        }
        return false;
    }

    /**
     * https://developers.google.com/identity/protocols/OAuth2WebServer#exchange-authorization-code
     * 
     * @param string $code
     */
    private function fetchTokenFromCode(string $code) {
        $body       = $this->array2wwwform([
            'code'          => $code,
            'client_id'     => $this->appConfig->client_id,
            'client_secret' => $this->appConfig->client_secret,
            'redirect_uri'  => $this->appConfig->redirect_uris[0],
            'grant_type'    => 'authorization_code',
        ]);
        $req        = new Request('POST', self::TOKEN_URL, self::CONTENT_TYPE, $body);
        $resp       = $this->client->send($req);
        $this->data = json_decode($resp->getBody());
    }

    /**
     * https://developers.google.com/apis-explorer/#p/oauth2/v2/oauth2.tokeninfo
     */
    private function fetchData(UsersDbInterface $db) {
        if (!$this->data->access_token) {
            throw new RequestException('No access token', new Request('GET', 'http://127.0.0.1'));
        }
        $url        = self::TOKENINFO_URL . '?access_token=' . urlencode($this->data->access_token);
        $req        = new Request('GET', $url, self::CONTENT_TYPE);
        $resp       = $this->client->send($req);
        $data       = json_decode($resp->getBody());
        $this->data = (object) array_merge((array) $this->data, (array) $data);

        if ($this->data->expires_in <= $this->authConfig['refresh_time']) {
            $this->refreshToken($db);
        }
    }

    /**
     * https://developers.google.com/identity/protocols/OAuth2WebServer#offline
     */
    private function refreshToken(UsersDbInterface $db): bool {
        $user     = $this->getUserName();
        $userData = (object) array_merge((array) $db->getUser($user), (array) $this->data);
        if (!isset($userData->refresh_token) || !$userData->refresh_token) {
            return false;
        }
        $body = $this->array2wwwform([
            'client_id'     => $this->appConfig->client_id,
            'client_secret' => $this->appConfig->client_secret,
            'refresh_token' => $userData->refresh_token,
            'grant_type'    => 'refresh_token',
        ]);
        $req  = new Request('POST', self::TOKEN_URL, self::CONTENT_TYPE, $body);
        $resp = $this->client->send($req);
        $data = json_decode($resp->getBody());

        $this->data = (object) array_merge((array) $this->data, (array) $data);

        return true;
    }

    /**
     * https://developers.google.com/identity/protocols/OAuth2WebServer#redirecting
     * all parameters description under:
     * https://developers.google.com/identity/protocols/OAuth2WebServer#creatingclient
     * 
     * @return string
     */
    private function getAuthUrl(): string {
        $url  = self::AUTH_URL;
        $glue = '?';
        foreach ($this->authConfig as $k => $v) {
            if (strlen($v) > 0) {
                $url  .= $glue . $k . '=' . urlencode($v);
                $glue = '&';
            }
        }
        return $url;
    }

    private function array2wwwform(array $a): string {
        $data = '';
        $glue = '';
        foreach ($a as $k => $v) {
            $data .= $glue . urlencode($k) . '=' . urlencode($v);
            $glue = '&';
        }
        return $data;
    }

}
