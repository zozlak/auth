    # Auth

A simple yet flexible library for authenticating against different providers.

Currently supported authorization providers:

* HTTP basic
* HTTP digest
* trusted header (e.g. set up by a Shibboleth)
* Google access_token
* fixed data (e.g. a fallback guest user)

Currently supported users database backends:

* PDO

## Usage

Simple example trying to authenticate with Google, then with HTTP basic and 
finally using a fixed `zzz` user as a fallback.

```php
namespace zozlak\auth;
require '/vendor/autoload.php';
$db = new usersDb\PdoDb('sqlite::memory:');
// init users
$db->putUser('aaa', authMethod\HttpBasic::pswdData('1234'));
$db->putUser('bbb', authMethod\HttpBasic::pswdData('1234'));
// create auth controller and add auth methods
$ctl   = new AuthController($db);
$ctl->addMethod(new GoogleToken(filter_input(INPUT_GET, 'token') ?? ''));
$ctl->addMethod(new HttpBasic('realm', false));
$ctl->addMethod(new Guest('zzz'));
// try to authenticate
if ($ctl->authenticate()) {
    print_r([$ctl->getUserName(), $ctl->getUserData()]);
} else {
    header('HTTP/1.1 401 Unauthorized');
    echo "Authentication failed\n";
}
```

### Caveats

Chaining some methods may be difficult. The main problem is some methods require
auxiliary requests to be made, e.g.:

* The HTTP digest method requires appropriate `WWW-Authenticate` HTTP header to 
  be provided to a client. Without such header client is unable to prepare
  correct credentials.
* Obtaining access token with OAuth2-based providers (e.g. Google) require
  redirection to external services.

Sending such auxiliary requests would stop resolution of other auth providers in 
the chain. On the other evaluation of other methods in the chain would stop full 
resolution of above-mentioned auth providers. Therefore they exclude each other.

### Using with REST services

In most cases it doesn't make sense 
