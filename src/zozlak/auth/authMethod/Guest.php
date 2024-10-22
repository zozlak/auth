<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace zozlak\auth\authMethod;

use BadMethodCallException;
use stdClass;
use Psr\Http\Message\ResponseInterface;
use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Description of Guest
 *
 * @author zozlak
 */
class Guest implements AuthMethodInterface {

    private string $user;
    private object $data;

    public function __construct(string $user, object | null $data = null) {
        $this->user = $user;
        $this->data = $data ?? new stdClass();
    }

    public function authenticate(UsersDbInterface $db, bool $strict): bool {
        return true;
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

    public function logout(UsersDbInterface $db, string $redirectUrl = ''): ResponseInterface | null {
        throw new BadMethodCallException('logout not supported');
    }
}
