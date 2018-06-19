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

/**
 * Description of Shibboleth
 *
 * @author zozlak
 */
class TrustedHeader implements AuthMethodInterface {

    private $userHeader;
    private $headersPrefix;
    private $headersList;
    private $user;
    private $data;

    public function __construct(string $userHeader,
                                string $headersPrefix = null,
                                array $headersList = []) {
        $this->userHeader    = $userHeader;
        $this->headersPrefix = $headersPrefix;
        $this->headersList   = $headersList;
        $this->data          = new stdClass();
    }

    public function authenticate(UsersDbInterface $db): bool {
        $user = filter_input(\INPUT_SERVER, $this->userHeader);
        if ($user === null) {
            return false;
        }
        $this->user = $user;

        $data = [];
        foreach ($this->headersList as $i) {
            $data[$i] = filter_input(\INPUT_SERVER, $i);
        }
        foreach ($_SERVER as $h => $i) {
            if (substr($h, 0, strlen($this->headersPrefix)) === $this->headersPrefix) {
                $data[$h] = $i;
            }
        }
        $this->data = (object) $data;
        
        return true;
    }

    public function getUserData(): stdClass {
        return $this->data;
    }

    public function getUserName(): string {
        return $this->user;
    }

}
