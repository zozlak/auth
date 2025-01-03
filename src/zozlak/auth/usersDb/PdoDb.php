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

namespace zozlak\auth\usersDb;

use PDO;
use PDOException;
use stdClass;

/**
 * Implementation of the UsersDbInterface using any PDO-compliant database as 
 * a backend.
 * 
 * Users data are storem as simple key-value pairs with key being a user name
 * and value being user's data serialized to JSON.
 *
 * @author zozlak
 */
class PdoDb implements UsersDbInterface {

    private PDO $pdo;
    private string $tableName;
    private string $userCol;
    private string $dataCol;

    public function __construct(string $connString, string $tableName = 'users',
                                string $userCol = 'user',
                                string $dataCol = 'data') {
        $this->tableName = $tableName;
        $this->userCol   = $userCol;
        $this->dataCol   = $dataCol;

        $this->pdo = new PDO($connString);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        try {
            $this->pdo->query("SELECT 1 FROM $this->tableName");
        } catch (PDOException $ex) {
            $this->pdo->query("CREATE TABLE $this->tableName($this->userCol text primary key, $this->dataCol text)");
        }
    }

    public function deleteUser(string $user): bool {
        $query = $this->pdo->prepare("DELETE FROM $this->tableName WHERE $this->userCol = ?");
        $query->execute([$user]);
        return $query->rowCount() === 1;
    }

    public function getUser(string $user): stdClass {
        $query = $this->pdo->prepare("SELECT $this->dataCol FROM $this->tableName WHERE $this->userCol = ?");
        $query->execute([$user]);
        $data  = $query->fetchColumn();
        if ($data === false) {
            throw new UserUnknownException();
        }
        return json_decode((string) $data) ?? new stdClass();
    }

    public function putUser(string $user, object | null $data = null,
                            bool $merge = true): bool {
        $data = $data ?? new stdClass();

        $update = true;
        try {
            $exData = $this->getUser($user);
            if ($merge) {
                $data = (object) array_merge((array) $exData, (array) $data);
            }
        } catch (UserUnknownException $ex) {
            $update = false;
        }

        if ($update) {
            $query = $this->pdo->prepare("UPDATE $this->tableName SET $this->dataCol = ? WHERE $this->userCol = ?");
            $query->execute([json_encode($data), $user]);
        } else {
            $query = $this->pdo->prepare("INSERT INTO $this->tableName ($this->userCol, $this->dataCol) VALUES (?, ?)");
            $query->execute([$user, json_encode($data)]);
        }

        return $update;
    }
}
