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

use stdClass;
use GuzzleHttp\Psr7\Response;
use zozlak\auth\usersDb\PdoDb;
use zozlak\auth\authMethod\Guest;
use zozlak\auth\authMethod\HttpBasic;
use zozlak\auth\authMethod\TrustedHeader;

/**
 * Description of AuthContollerStaticTest
 *
 * @author zozlak
 */
class AuthContollerTest extends \PHPUnit\Framework\TestCase {

    private PdoDb $userDb;
    private AuthController $auth;

    public function setUp(): void {
        parent::setUp();
        $this->userDb = new PdoDb('sqlite::memory:');
        $this->auth   = new AuthController($this->userDb);
        foreach (array_keys($_SERVER) as $i) {
            unset($_SERVER[$i]);
        }
    }

    public function testAuthenticate(): void {
        $this->assertFalse($this->auth->authenticate(false));
        $this->assertFalse($this->auth->authenticate(true));

        $this->auth->addMethod(new HttpBasic('realm'));
        $this->assertFalse($this->auth->authenticate(false));
        $this->assertFalse($this->auth->authenticate(true));

        $_SERVER['HTTP_AUTHORIZATION'] = 'Basic ' . base64_encode('foo:bar');
        $this->assertFalse($this->auth->authenticate(false));
        $this->assertFalse($this->auth->authenticate(true));

        $this->auth->addMethod(new Guest('guest'));
        $this->assertTrue($this->auth->authenticate(false));
        $this->assertEquals('guest', $this->auth->getUserName());
        $this->assertFalse($this->auth->authenticate(true));

        $this->userDb->putUser('foo', HttpBasic::pswdData('bar'));
        $this->assertTrue($this->auth->authenticate(false));
        $this->assertEquals('foo', $this->auth->getUserName());
        $this->assertTrue($this->auth->authenticate(true));
        $this->assertEquals('foo', $this->auth->getUserName());
    }

    public function testAdvertise(): void {
        $this->assertNull($this->auth->advertise());

        $this->auth->addMethod(new Guest('guest'), AuthController::ADVERTISE_ALWAYS);
        $this->assertNull($this->auth->advertise());

        $this->auth->addMethod(new HttpBasic('realm'), AuthController::ADVERTISE_NONE);
        $this->assertNull($this->auth->advertise());

        $basic2Resp                    = new Response(401, ['www-authenticate' => 'Basic realm="realm2"']);
        $this->auth->addMethod(new HttpBasic('realm2'), AuthController::ADVERTISE_ONCE);
        $this->assertEquals($basic2Resp, $this->auth->advertise());
        $_SERVER['HTTP_AUTHORIZATION'] = 'Basic ' . base64_encode('foo:bar');
        $this->assertNull($this->auth->advertise());

        $basic3Resp = new Response(401, ['www-authenticate' => 'Basic realm="realm3"']);
        $this->auth->addMethod(new HttpBasic('realm3'), AuthController::ADVERTISE_ALWAYS);
        $this->assertEquals($basic3Resp, $this->auth->advertise());

        $this->auth->addMethod(new HttpBasic('realm4'), AuthController::ADVERTISE_ALWAYS);
        $this->assertEquals($basic3Resp, $this->auth->advertise());
    }

    public function testLogout(): void {
        $this->assertNull($this->auth->logout());
        $this->assertNull($this->auth->logout('redirectUrl'));

        $this->auth->addMethod(new Guest('guest'));
        $this->assertNull($this->auth->logout());
        $this->assertNull($this->auth->logout('redirectUrl'));

        $this->auth->addMethod(new HttpBasic('realm'));
        $this->assertNull($this->auth->logout());
        $this->assertNull($this->auth->logout('redirectUrl'));

        $_SERVER['AUTHORIZATION'] = 'Basic ' . base64_encode('foo:bar');
        $this->auth->addMethod(new HttpBasic('realm'));
        $headers                  = ['www-authenticate' => 'Basic realm="realm"'];
        $this->assertEquals(new Response(401, $headers), $this->auth->logout());
        $resp                     = $this->auth->logout('redirectUrl');
        $this->assertEquals(401, $resp->getStatusCode());
        $this->assertCount(2, $resp->getHeaders());
        $this->assertEquals(['Basic realm="realm"'], $resp->getHeader('www-authenticate'));
        $this->assertEquals(['0: url=redirectUrl'], $resp->getHeader('refresh'));
    }

    public function testUserData(): void {
        try {
            $this->auth->getUserData();
            $this->assertTrue(false);
        } catch (UnauthorizedException) {
            $this->assertTrue(true);
        }
        try {
            $this->auth->putUserData(new stdClass());
            $this->assertTrue(false);
        } catch (UnauthorizedException) {
            $this->assertTrue(true);
        }

        // auth method addded but no credentials&data in the request
        $this->auth->addMethod(new TrustedHeader('EPPN', 'DATA_'));
        $this->assertFalse($this->auth->authenticate(false));
        try {
            $this->auth->getUserData();
            $this->assertTrue(false);
        } catch (UnauthorizedException) {
            $this->assertTrue(true);
        }
        try {
            $this->auth->putUserData(new stdClass());
            $this->assertTrue(false);
        } catch (UnauthorizedException) {
            $this->assertTrue(true);
        }

        // guest auth method added with some fixed data
        $userData = (object) ['foo' => 'bar'];
        $this->auth->addMethod(new authMethod\Guest('guestUser', $userData));
        $this->assertTrue($this->auth->authenticate(false));
        $this->assertEquals('guestUser', $this->auth->getUserName());
        $this->assertEquals($userData, $this->auth->getUserData());
        $this->assertEquals($userData, $this->userDb->getUser('guestUser'));

        // request data matching the trusted header method
        // user name matches the guest method fixed user name so user data is merged
        $_SERVER['EPPN']         = 'guestUser';
        $_SERVER['DATA_V1']      = 'sampleValue';
        $userDataMerged          = $userData;
        $userDataMerged->DATA_V1 = $_SERVER['DATA_V1'];
        $this->assertTrue($this->auth->authenticate(false));
        $this->assertEquals('guestUser', $this->auth->getUserName());
        $this->assertEquals($userDataMerged, $this->auth->getUserData());
        $this->assertEquals($userDataMerged, $this->userDb->getUser('guestUser'));

        // request data matching the trusted header method
        // distinct user name
        $_SERVER['EPPN'] = 'eppnUser';
        $userData2       = (object) ['DATA_V1' => 'sampleValue'];
        $this->assertTrue($this->auth->authenticate(false));
        $this->assertEquals('eppnUser', $this->auth->getUserName());
        $this->assertEquals($userData2, $this->auth->getUserData());
        $this->assertEquals($userData2, $this->userDb->getUser('eppnUser'));
    }
}
