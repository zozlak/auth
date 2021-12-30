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
use stdClass;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;
use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Simple Google access_token-based authentication provider.
 * 
 * It assumes client already has a valid token. No help is provided for 
 * obtaining the token nor refreshing an expired one.
 *
 * Amount of data provided by the getUserData() method solely depends on the 
 * token and this provider doesn't make any assumptions about it. Basically all 
 * the data returned for the provided token by the https://www.googleapis.com/oauth2/v3/tokeninfo
 * Google API endpoint are returned.
 * 
 * @author zozlak
 */
class GoogleToken implements AuthMethodInterface {

    const API_URL = 'https://www.googleapis.com/oauth2/v3/tokeninfo';

    private string $token;
    private string $usernameField;
    private object $data;

    /**
     * 
     * @param string $token Google access_token
     * @param string $usernameField field in the data returned for the token by
     *   the https://www.googleapis.com/oauth2/v3/tokeninfo Google API endpoint
     *   to be used as a user name, e.g. 'email' or 'userId'
     */
    public function __construct(string $token, string $usernameField = 'email') {
        $this->token         = $token;
        $this->usernameField = $usernameField;
    }

    public function authenticate(UsersDbInterface $db): bool {
        $client = new Client();
        $req    = new Request('GET', self::API_URL . '?access_token=' . $this->token);
        try {
            $resp  = $client->send($req);
            $data  = json_decode($resp->getBody());
            $field = $this->usernameField;
            if ($data === null || isset($data->err) || !isset($data->$field)) {
                return false;
            }
            $this->data = $data;
            return true;
        } catch (RequestException $ex) {
            return false;
        }
    }

    public function getUserData(): object {
        return $this->data;
    }

    public function getUserName(): string {
        $field = $this->usernameField;
        return $this->data->$field;
    }

    public function advertise(bool $onFailure): bool {
        throw new BadMethodCallException('advertising not supported');
    }

}
