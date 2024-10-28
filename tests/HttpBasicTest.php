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

use GuzzleHttp\Psr7\Response;
use zozlak\auth\authMethod\HttpBasic;

/**
 * Description of HttpBasicTest
 *
 * @author zozlak
 */
class HttpBasicTest extends AuthMethodTestBase {

    const REALM = 'sample realm';
    const PSWD  = 'bar';

    public function setUp(): void {
        parent::setUp();
        $this->usersDb->putUser(self::VALID_USER, HttpBasic::pswdData(self::PSWD));
        $this->auth = new HttpBasic(self::REALM);
        unset($_SERVER['HTTP_AUTHORIZATION']);
        unset($_SERVER['AUTHORIZATION']);
    }

    public function testAuthenticate(): void {
        // no credentials
        $this->assertFalse($this->auth->authenticate($this->usersDb, false));
        $this->assertFalse($this->auth->authenticate($this->usersDb, true));

        // valid credentials
        $_SERVER['HTTP_AUTHORIZATION'] = $this->getAuthHeader(self::VALID_USER, self::PSWD);
        $this->assertTrue($this->auth->authenticate($this->usersDb, false));
        $this->assertTrue($this->auth->authenticate($this->usersDb, true));

        $_SERVER['AUTHORIZATION'] = $_SERVER['HTTP_AUTHORIZATION'];
        unset($_SERVER['HTTP_AUTHORIZATION']);
        $this->assertTrue($this->auth->authenticate($this->usersDb, false));
        $this->assertTrue($this->auth->authenticate($this->usersDb, true));

        // wrong password
        $_SERVER['AUTHORIZATION'] = $this->getAuthHeader(self::VALID_USER, 'wrongPassword');
        $this->assertFalse($this->auth->authenticate($this->usersDb, false));
        try {
            $this->auth->authenticate($this->usersDb, true);
            $this->assertTrue(false);
        } catch (UnauthorizedException) {
            $this->assertTrue(true);
        }

        // nonexisting user
        $_SERVER['AUTHORIZATION'] = $this->getAuthHeader('wrongUser', self::PSWD);
        $this->assertFalse($this->auth->authenticate($this->usersDb, false));
        try {
            $this->auth->authenticate($this->usersDb, true);
            $this->assertTrue(false);
        } catch (UnauthorizedException) {
            $this->assertTrue(true);
        }
    }

    public function testLogout(): void {
        $this->assertNull($this->auth->logout($this->usersDb));

        $_SERVER['AUTHORIZATION'] = $this->getAuthHeader('any user', 'any pswd');

        $refResp = new Response(401, ['www-authenticate' => 'Basic realm="' . self::REALM . '"']);
        $this->assertEquals($refResp, $this->auth->logout($this->usersDb));

        $headers = [
            'www-authenticate' => 'Basic realm="' . self::REALM . '"',
            'refresh'          => '0; url=redirectUrl',
        ];
        $resp    = $this->auth->logout($this->usersDb, 'redirectUrl');
        $this->assertEquals(401, $resp->getStatusCode());
        $this->assertCount(2, $resp->getHeaders());
        $this->assertEquals([$headers['refresh']], $resp->getHeader('refresh'));
        $this->assertEquals([$headers['www-authenticate']], $resp->getHeader('www-authenticate'));
    }

    public function testGetUserData(): void {
        $this->assertEquals(new \stdClass(), $this->auth->getUserData());

        $_SERVER['HTTP_AUTHORIZATION'] = $this->getAuthHeader(self::VALID_USER, self::PSWD);
        $this->auth->authenticate($this->usersDb, false);
        $this->assertEquals(self::VALID_USER, $this->auth->getUserName());
    }

    public function testAdvertise(): void {
        $refResp = new Response(401, ['www-authenticate' => 'Basic realm="' . self::REALM . '"']);

        $resp = $this->auth->advertise(false);
        $this->assertEquals($refResp, $resp);

        $_SERVER['HTTP_AUTHORIZATION'] = $this->getAuthHeader(self::VALID_USER, self::PSWD);
        $this->assertNull($this->auth->advertise(false));
        $resp                          = $this->auth->advertise(true);
        $this->assertEquals($refResp, $resp);
    }

    private function getAuthHeader(string $user, string $pswd): string {
        return 'Basic :' . base64_encode("$user:$pswd");
    }
}
