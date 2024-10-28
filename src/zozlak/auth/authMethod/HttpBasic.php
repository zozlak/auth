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
use GuzzleHttp\Psr7\Response;
use zozlak\auth\usersDb\UsersDbInterface;
use zozlak\auth\usersDb\UserUnknownException;
use zozlak\auth\UnauthorizedException;

/**
 * Description of HttpBasic
 *
 * @author zozlak
 */
class HttpBasic implements AuthMethodInterface {

    static public function pswdData(string $pswd): stdClass {
        return (object) ['pswd' => password_hash($pswd, PASSWORD_DEFAULT)];
    }

    private string $realm;
    private string $user;

    public function __construct(string $realm) {
        $this->realm = $realm;
    }

    public function authenticate(UsersDbInterface $db, bool $strict): bool {
        $user    = $pswd    = null;
        $reqData = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['AUTHORIZATION'] ?? '');
        if (strtolower(substr($reqData, 0, 6)) === 'basic ') {
            $reqData = base64_decode(trim(substr($reqData, 6)));
            $delpos  = strpos($reqData, ':');
            $user    = substr($reqData, 0, (int) $delpos);
            $pswd    = substr($reqData, $delpos + 1);
        } else {
            return false;
        }

        try {
            $data = $db->getUser($user);
            $hash = $data->pswd ?? '';
            if (password_verify($pswd, $hash)) {
                $this->user = $user;
                return true;
            }
        } catch (UserUnknownException $ex) {
            
        }
        if ($strict) {
            throw new UnauthorizedException();
        }
        return false;
    }

    public function advertise(bool $onFailure): Response | null {
        if (!isset($_SERVER['PHP_AUTH_USER']) && !isset($_SERVER['HTTP_AUTHORIZATION']) && !isset($_SERVER['AUTHORIZATION']) || $onFailure) {
            return new Response(401, ['www-authenticate' => 'Basic realm="' . $this->realm . '"']);
        }
        return null;
    }

    public function logout(UsersDbInterface $db, string $redirectUrl = ''): Response | null {
        if (!isset($_SERVER['PHP_AUTH_USER']) && !isset($_SERVER['HTTP_AUTHORIZATION']) && !isset($_SERVER['AUTHORIZATION'])) {
            return null;
        }
        $headers = ['www-authenticate' => 'Basic realm="' . $this->realm . '"'];
        if (!empty($redirectUrl)) {
            $headers['refresh'] = '0; url=' . $redirectUrl;
        }
        return new Response(401, $headers);
    }

    public function getUserData(): stdClass {
        return new stdClass();
    }

    public function getUserName(): string {
        return $this->user;
    }
}
