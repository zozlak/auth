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

use zozlak\auth\authMethod\TrustedHeader;

/**
 * Description of TrustedHeaderTest
 *
 * @author zozlak
 */
class TrustedHeaderTest extends AuthMethodTestBase {

    const HEADER             = 'FOO';
    const DATA_HEADER_PREFIX = 'DATA_';
    const DATA_HEADER_LIST   = ['BAR_1', 'BAR_2'];

    public function setUp(): void {
        parent::setUp();
        $this->auth = new TrustedHeader(self::HEADER, self::DATA_HEADER_PREFIX, self::DATA_HEADER_LIST);
        foreach (array_keys($_SERVER) as $i) {
            unset($_SERVER[$i]);
        }
    }

    public function testAuthenticate(): void {
        $this->assertFalse($this->auth->authenticate($this->usersDb, false));
        $this->assertFalse($this->auth->authenticate($this->usersDb, true));

        $_SERVER[self::HEADER] = 'any user';
        $this->assertTrue($this->auth->authenticate($this->usersDb, false));
        $this->assertTrue($this->auth->authenticate($this->usersDb, true));
    }

    public function testGetUserData(): void {
        $_SERVER[self::HEADER] = 'any user';
        $refData               = array_combine(self::DATA_HEADER_LIST, [null, null]);
        $refData               = (object) $refData;

        $this->auth->authenticate($this->usersDb, false);
        $this->assertEquals('any user', $this->auth->getUserName());
        $this->assertEquals($refData, $this->auth->getUserData());

        $_SERVER[self::DATA_HEADER_PREFIX . 'FOO'] = 'fooVal';
        $_SERVER[self::DATA_HEADER_LIST[0]]        = 'barVal';
        $_SERVER['BAR_3']                          = 'skipVal';
        $refData->DATA_FOO                         = 'fooVal';
        $refData->BAR_1                            = 'barVal';
        $this->auth->authenticate($this->usersDb, false);
        $this->assertEquals('any user', $this->auth->getUserName());
        $this->assertEquals($refData, $this->auth->getUserData());
    }
}