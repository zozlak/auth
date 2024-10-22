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
use Psr\Http\Message\ResponseInterface;
use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Description of Shibboleth
 *
 * @author zozlak
 */
class TrustedHeader implements AuthMethodInterface {

    private string $userHeader;
    private string $headersPrefix;

    /**
     * 
     * @var array<string>
     */
    private array $headersList;
    private string $user;
    private object $data;

    /**
     * Sets up the authentication provider.
     * 
     * @param string $userHeader HTTP header storing user login (e.g. HTTP_EPPN)
     * @param string $headersPrefix name prefix of HTTP headers storing user
     *   data (e.g. HTTP_SHIB_)
     * @param array<string> $headersList explicit list of HTTP header names storing user
     *   data
     */
    public function __construct(string $userHeader, string $headersPrefix = '',
                                array $headersList = []) {
        $this->userHeader    = $userHeader;
        $this->headersPrefix = $headersPrefix;
        $this->headersList   = $headersList;
        $this->data          = new stdClass();
    }

    public function authenticate(UsersDbInterface $db, bool $strict): bool {
        $user = $_SERVER[$this->userHeader] ?? null;
        if ($user === null || $user === '(null)') {
            return false;
        }
        $this->user = $user;

        $data = [];
        foreach ($this->headersList as $i) {
            $data[$i] = $_SERVER[$i] ?? null;
        }
        foreach ($_SERVER as $h => $i) {
            if (substr($h, 0, strlen($this->headersPrefix)) === $this->headersPrefix) {
                $data[$h] = $i;
            }
        }
        $this->data = (object) $data;

        return true;
    }

    public function logout(UsersDbInterface $db, string $redirectUrl = ''): ResponseInterface | null {
        throw new BadMethodCallException('logout not supported');
    }

    public function getUserData(): object {
        return $this->data;
    }

    public function getUserName(): string {
        return $this->user;
    }

    public function advertise(bool $onFailure): ResponseInterface | null {
        throw new BadMethodCallException('advertising not supported');
    }
}
