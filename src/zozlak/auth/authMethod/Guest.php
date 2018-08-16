<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace zozlak\auth\authMethod;

use BadMethodCallException;
use stdClass;
use zozlak\auth\usersDb\UsersDbInterface;

/**
 * Description of Guest
 *
 * @author zozlak
 */
class Guest implements AuthMethodInterface {

    private $user;
    private $data;

    public function __construct(string $user, stdClass $data = null) {
        $this->user = $user;
        $this->data = $data ?? new stdClass();
    }

    public function authenticate(UsersDbInterface $db): bool {
        return true;
    }

    public function getUserData(): stdClass {
        return $this->data;
    }

    public function getUserName(): string {
        return $this->user;
    }

    public function advertise(bool $onFailure): bool {
        throw new BadMethodCallException('advertising not supported');
    }

}
