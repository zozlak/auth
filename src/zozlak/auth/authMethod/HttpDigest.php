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
 * Description of HttpDigest
 *
 * @author zozlak
 */
class HttpDigest implements AuthMethodInterface {

    static private function getHa1(string $realm, string $user, string $pswd): string {
        return md5($user . ':' . $realm . ':' . $pswd);
    }

    static public function pswdData(string $realm, string $user, string $pswd): object {
        return (object) ['ha1' => self::getHa1($realm, $user, $pswd)];
    }

    private string $realm;
    private string $user;

    public function __construct(string $realm) {
        $this->realm = $realm;
    }

    public function authenticate(UsersDbInterface $db, bool $strict): bool {
        $reqData = $this->getRequestData();
        if ($reqData === null) {
            return false;
        }
        try {
            $data = $db->getUser($reqData['username']);
            if (strlen($data->ha1 ?? '') === 0) {
                return false;
            }
            $ha2       = md5(($_SERVER['REQUEST_METHOD'] ?? '') . ':' . $reqData['uri']);
            $nonce     = $reqData['nonce'] . ':' . $reqData['nc'] . ':' . $reqData['cnonce'] . ':' . $reqData['qop'];
            $validResp = md5($data->ha1 . ':' . $nonce . ':' . $ha2);
            if ($reqData['response'] === $validResp) {
                $this->user = $reqData['username'];
                return true;
            }
        } catch (UserUnknownException $ex) {
            
        }
        if ($strict) {
            throw new UnauthorizedException();
        }
        return false;
    }

    public function logout(UsersDbInterface $db, string $redirectUrl = ''): Response | null {
        if (!isset($_SERVER['PHP_AUTH_DIGEST'])) {
            return null;
        }
        $headers = [];
        if (!empty($redirectUrl)) {
            $headers['Refresh'] = '0; url=' . $redirectUrl;
        }
        return new Response(401, $headers);
    }

    public function getUserData(): object {
        return new stdClass();
    }

    public function getUserName(): string {
        return $this->user;
    }

    public function advertise(bool $onFailure): Response | null {
        if ($this->getRequestData() === null || $onFailure) {
            $headers                     = [];
            $headers['WWW-Authenticate'] = 'Digest realm="' . $this->realm . '",qop="auth",nonce="' . bin2hex(random_bytes(16)) . '",opaque="' . md5($this->realm) . '"';
            return new Response(401, $headers);
        }
        return null;
    }

    /**
     * 
     * @return array<mixed>|null
     */
    private function getRequestData(): ?array {

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

        $raw = $this->getDigestHeader();
        if (!empty($raw)) {
            $matches = null;
            preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $raw, $matches, PREG_SET_ORDER);
        }

        $data = [];
        foreach ($matches ?? [] as $m) {
            $data[$m[1]] = $m[3] ? $m[3] : $m[4];
            unset($parts[$m[1]]);
        }

        return count($parts) > 0 ? null : $data;
    }

    private function getDigestHeader(): string {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['AUTHORIZATION'] ?? '');
        if (strtolower(substr($header, 0, 8)) === 'digest ') {
            return substr($header, 8);
        }
        return '';
    }
}
