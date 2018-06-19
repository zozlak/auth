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

namespace zozlak\auth;

use RuntimeException;
use stdClass;
use zozlak\auth\authMethod\AuthMethodInterface;
use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Allows to chain authentication methods.
 * Authentication attempts are stopped after first method returns a success.
 *
 * @author zozlak
 */
class AuthController {
    
    private $authChain = [];
    private $valid = -1;
    private $usersDb;

    /**
     * 
     * @param UsersDbInterface $db database storing users data (e.g. passwords
     *   or preferences)
     */
    public function __construct(UsersDbInterface $db) {
        $this->usersDb = $db;
    }

    public function addMethod(AuthMethodInterface $method): AuthController {
        $this->authChain[] = $method;
        return $this;
    }

    public function authenticate(): bool {
        $this->valid = -1;
        foreach ($this->authChain as $i => $authMethod) {
            /* @var $authMethod \zozlak\auth\authMethod\AuthMethodInterface */
            if ($authMethod->authenticate($this->usersDb)) {
                $this->valid = $i;
                $this->usersDb->putUser($authMethod->getUserName(), $authMethod->getUserData());
                return true;
            }
        }
        return false;
    }
    
    public function getUserName() {
        if ($this->valid < 0) {
            throw new RuntimeException('Unauthorized', 401);
        }
        return $this->authChain[$this->valid]->getUserName();
    }

    public function getUserData(): stdClass {
        return $this->usersDb->getUser($this->getUserName());
    }

    public function putUserData(stdClass $data, bool $merge = true) {
        return $this->usersDb->putUser($this->getUserName(), $data, $merge);
    }

}
