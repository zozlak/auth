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
use GuzzleHttp\Psr7\Response;
use zozlak\auth\usersDb\UsersDbInterface;
use zozlak\auth\usersDb\UserUnknownException;
use zozlak\auth\UnauthorizedException;

/**
 * Auth based on automatically expiring random tokens.
 * 
 * Before generating a token you should typically authenticate user with other
 * method. Then you can switch to a token.
 * 
 * @author zozlak
 */
class Token implements AuthMethodInterface {

    static public function createToken(stdClass $data, string $user,
                                       int $expirationTime = 600): string {

        $token = '';
        for ($i = 0; $i < 32; $i++) {
            $token .= chr(random_int(32, 126));
        }
        $token        = $user . ':' . password_hash($token, PASSWORD_DEFAULT);
        $token        = [
            'token'   => $token,
            'expires' => time() + $expirationTime
        ];
        $tokens       = $data->tokens ?? [];
        $tokens[]     = $token;
        $data->tokens = $tokens;
        return $token['token'];
    }

    private object $data;
    private string $token;
    private int $expTime;

    /**
     * 
     * @param string $token access token
     * @param int $expirationTime for how many seconds token should be 
     *   extended when matched
     */
    public function __construct(string $token, int $expirationTime = 600) {
        $this->token   = $token;
        $this->expTime = $expirationTime;
    }

    public function authenticate(UsersDbInterface $db, bool $strict): bool {
        $user = $this->getUserName();
        try {
            $data = $db->getUser($user);
        } catch (UserUnknownException $ex) {
            if ($strict) {
                throw new UnauthorizedException();
            }
            return false;
        }

        $passed      = false;
        $validTokens = [];
        $time        = time();
        foreach ($data->tokens ?? [] as $i) {
            if ($i->expires >= $time) {
                if ($i->token === $this->token) {
                    $i->expires = $time + $this->expTime;
                    $passed     = true;
                }
                $validTokens[] = $i;
            }
        }

        $data->tokens = $validTokens;
        $db->putUser($user, $data);

        if ($passed) {
            $this->data = $data;
        } elseif ($strict) {
            throw new UnauthorizedException();
        }
        return $passed;
    }

    public function logout(UsersDbInterface $db, string $redirectUrl = ''): Response | null {
        $user = $this->getUserName();
        try {
            $data = $db->getUser($user);
            for ($i = 0; $i < count($data->tokens ?? []); $i++) {
                if ($data->tokens[$i]->token === $this->token) {
                    unset($data->tokens[$i]);
                    $db->putUser($user, $data);
                    $resp = !empty($redirectUrl) ? new Response(302, ['Location' => $redirectUrl]) : new Response(201);
                    return $resp;
                }
            }
        } catch (UserUnknownException $ex) {
            
        }
        return null;
    }

    public function getUserData(): object {
        return $this->data;
    }

    public function getUserName(): string {
        $token = explode(':', $this->token);
        return array_shift($token);
    }

    public function advertise(bool $onFailure): Response | null {
        throw new BadMethodCallException('advertising not supported');
    }
}
