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

use zozlak\auth\authMethod\Guest;

/**
 * Description of GuestTest
 *
 * @author zozlak
 */
class GuestTest extends AuthMethodTestBase {

    const DATA = ['foo' => 'bar'];

    public function setUp(): void {
        parent::setUp();
        $this->auth = new Guest(self::VALID_USER, (object) self::DATA);
    }

    public function testAuthenticate(): void {
        $this->assertTrue($this->auth->authenticate($this->usersDb, false));
        $this->assertTrue($this->auth->authenticate($this->usersDb, true));
    }

    public function testGetUserData(): void {
        $this->assertEquals(self::VALID_USER, $this->auth->getUserName());
        $this->assertEquals((object) self::DATA, $this->auth->getUserData());
    }
}
