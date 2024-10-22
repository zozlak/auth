<?php

/*
 * The MIT License
 *
 * Copyright 2024 zozlak.
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
use zozlak\auth\usersDb\PdoDb;
use zozlak\auth\authMethod\AuthMethodInterface;

/**
 * Description of AuthMethodTestTrait
 *
 * @author zozlak
 */
class AuthMethodTestBase extends \PHPUnit\Framework\TestCase {

    const VALID_USER = 'foo';

    protected AuthMethodInterface $auth;
    protected PdoDb $usersDb;

    public function setUp(): void {
        parent::setUp();
        $this->usersDb = new PdoDb('sqlite::memory:');
    }

    /**
     * Default variant testing for BadMethodCall a.k.a. not implemented
     */
    public function testLogout(): void {
        try {
            $this->auth->logout($this->usersDb);
            $this->assertTrue(false);
        } catch (BadMethodCallException) {
            $this->assertTrue(true);
        }
    }

    /**
     * Default variant testing for BadMethodCall a.k.a. not implemented
     */
    public function testAdvertise(): void {
        try {
            $this->assertNull($this->auth->advertise(false));
            $this->assertTrue(false);
        } catch (BadMethodCallException) {
            $this->assertTrue(true);
        }
        try {
            $this->assertNull($this->auth->advertise(true));
            $this->assertTrue(false);
        } catch (BadMethodCallException) {
            $this->assertTrue(true);
        }
    }
}
