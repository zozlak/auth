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
 * Description of HttpBasic
 *
 * @author zozlak
 */
class HttpBasic implements AuthMethodInterface {

    static public function pswdData(string $pswd): stdClass {
        return (object) ['pswd' => password_hash($pswd, PASSWORD_DEFAULT)];
    }

    private $realm;
    private $user;

    public function __construct(string $realm) {
        $this->realm = $realm;
    }

    public function authenticate(UsersDbInterface $db): bool {
        $user    = $pswd    = null;
        $reqData = $_SERVER['AUTHORIZATION'] ?? '';
        if (strtolower(substr($reqData, 0, 6)) === 'basic ') {
            $reqData = base64_decode(trim(substr($reqData, 6)));
            $delpos  = strpos($reqData, ':');
            $user    = substr($reqData, 0, $delpos);
            $pswd    = substr($reqData, $delpos + 1);
        }

        if ($user === null) {
            return false;
        }
        try {
            $data = $db->getUser($user ?? '');
            $hash = $data->pswd ?? '';
            if (password_verify($pswd, $hash)) {
                $this->user = $user;
                return true;
            }
            return false;
        } catch (UserUnknownException $ex) {
            return false;
        }
    }

    public function advertise(bool $onFailure): bool {
        if (!isset($_SERVER['PHP_AUTH_USER']) || $onFailure) {
            header('WWW-Authenticate: Basic realm="' . $this->realm . '"');
            return true;
        }
        return false;
    }

    public function getUserData(): stdClass {
        return new stdClass();
    }

    public function getUserName(): string {
        return $this->user;
    }

}
