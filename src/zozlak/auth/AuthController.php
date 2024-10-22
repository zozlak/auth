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

use BadMethodCallException;
use stdClass;
use Psr\Http\Message\ResponseInterface;
use zozlak\auth\authMethod\AuthMethodInterface;
use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Allows to chain authentication methods.
 * Authentication attempts are stopped after first method returns a success.
 *
 * @author zozlak
 */
class AuthController {

    const ADVERTISE_NONE   = 1;
    const ADVERTISE_ONCE   = 2;
    const ADVERTISE_ALWAYS = 3;

    /**
     * 
     * @var array<AuthMethodInterface>
     */
    private array $authChain = [];

    /**
     * 
     * @var array<int>
     */
    private array $authAdvertise = [];
    private int $valid         = -1;
    private UsersDbInterface $usersDb;

    /**
     * 
     * @param UsersDbInterface $db database storing users data (e.g. passwords
     *   or preferences)
     */
    public function __construct(UsersDbInterface $db) {
        $this->usersDb = $db;
    }

    public function addMethod(AuthMethodInterface $method,
                              int $advertise = self::ADVERTISE_NONE): AuthController {
        if (!in_array($advertise, [self::ADVERTISE_NONE, self::ADVERTISE_ONCE, self::ADVERTISE_ALWAYS])) {
            throw new BadMethodCallException('advertise parameter must be one of ADVERTISE_NONE, ADVERTISE_ONCE and ADVERTISE_ALWAYS');
        }
        $this->authChain[]     = $method;
        $this->authAdvertise[] = $advertise;
        return $this;
    }

    public function authenticate(bool $strict): bool {
        $this->valid = -1;
        try {
            foreach ($this->authChain as $i => $authMethod) {
                /* @var $authMethod \zozlak\auth\authMethod\AuthMethodInterface */
                $resp = $authMethod->authenticate($this->usersDb, $strict);
                if ($resp !== false) {
                    $this->valid = $i;
                    $this->usersDb->putUser($authMethod->getUserName(), $authMethod->getUserData());
                    return true;
                }
            }
        } catch (UnauthorizedException) {
            
        }
        return false;
    }

    public function advertise(): ResponseInterface | null {
        foreach ($this->authChain as $i => $authMethod) {
            if ($this->authAdvertise[$i] >= self::ADVERTISE_ONCE) {
                try {
                    $resp = $authMethod->advertise($this->authAdvertise[$i] === self::ADVERTISE_ALWAYS);
                    if ($resp) {
                        return $resp;
                    }
                } catch (BadMethodCallException) {
                    
                }
            }
        }
        return null;
    }

    public function logout(string $redirectUrl = ''): ResponseInterface | null {
        foreach ($this->authChain as $i => $authMethod) {
            /* @var $authMethod \zozlak\auth\authMethod\AuthMethodInterface */
            try {
                $resp = $authMethod->logout($this->usersDb, $redirectUrl);
                if ($resp !== null) {
                    $this->valid = -1;
                    return $resp;
                }
            } catch (BadMethodCallException) {
                
            }
        }
        return null;
    }

    public function getUserName(): string {
        if ($this->valid < 0) {
            throw new UnauthorizedException();
        }
        return $this->authChain[$this->valid]->getUserName();
    }

    public function getUserData(): object {
        return $this->usersDb->getUser($this->getUserName());
    }

    public function putUserData(object $data, bool $merge = true): bool {
        return $this->usersDb->putUser($this->getUserName(), $data, $merge);
    }
}
