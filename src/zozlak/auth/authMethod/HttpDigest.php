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

use stdClass;
use zozlak\auth\usersDb\UsersDbInterface;
use zozlak\auth\usersDb\UserUnknownException;

/**
 * Description of HttpDigest
 *
 * @author zozlak
 */
class HttpDigest implements AuthMethodInterface {

    static private function getHa1(string $realm, string $user, string $pswd) {
        return md5($user . ':' . $realm . ':' . $pswd);
    }

    static public function pswdData(string $realm, string $user, string $pswd): stdClass {
        return (object) ['ha1' => self::getHa1($realm, $user, $pswd)];
    }

    private $realm;
    private $user;

    public function __construct(string $realm) {
        $this->realm = $realm;
    }

    public function authenticate(UsersDbInterface $db): bool {
        $reqData = $this->getRequestData();
        if (!$reqData) {
            return false;
        }
        try {
            $data = $db->getUser($reqData['username']);
            if (strlen($data->ha1 ?? '') === 0) {
                return false;
            }
            $ha2       = md5(filter_input(\INPUT_SERVER, 'REQUEST_METHOD') . ':' . $reqData['uri']);
            $nonce     = $reqData['nonce'] . ':' . $reqData['nc'] . ':' . $reqData['cnonce'] . ':' . $reqData['qop'];
            $validResp = md5($data->ha1 . ':' . $nonce . ':' . $ha2);
            if ($reqData['response'] === $validResp) {
                $this->user = $reqData['username'];
                return true;
            }
            return false;
        } catch (UserUnknownException $ex) {
            return false;
        }
    }

    public function getUserData(): stdClass {
        return new stdClass();
    }

    public function getUserName(): string {
        return $this->user;
    }

    public function advertise(bool $onFailure): bool {
        if (!$this->getRequestData() || $onFailure) {
            header('WWW-Authenticate: Digest realm="' . $this->realm . '",qop="auth",nonce="' . uniqid() . '",opaque="' . md5($this->realm) . '"');
            return true;
        }
        return false;
    }

    private function getRequestData() {

        $parts = [
            'nonce'    => 1,
            'nc'       => 1,
            'cnonce'   => 1,
            'qop'      => 1,
            'username' => 1,
            'uri'      => 1,
            'response' => 1
        ];
        $keys  = implode('|', array_keys($parts));

        $raw     = $_SERVER['PHP_AUTH_DIGEST'] ?? '';
        $matches = null;
        preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $raw, $matches, PREG_SET_ORDER);

        $data = [];
        foreach ($matches as $m) {
            $data[$m[1]] = $m[3] ? $m[3] : $m[4];
            unset($parts[$m[1]]);
        }

        return count($parts) > 0 ? false : $data;
    }

}
