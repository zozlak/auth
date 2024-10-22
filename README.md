# Auth

[![Latest Stable Version](https://poser.pugx.org/zozlak/auth/v/stable)](https://packagist.org/packages/zozlak/auth)
![Build status](https://github.com/acdh-oeaw/arche-core/workflows/phpunit/badge.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/zozlak/auth/badge.svg?branch=master)](https://coveralls.io/github/zozlak/auth?branch=master)
[![License](https://poser.pugx.org/zozlak/auth/license)](https://packagist.org/packages/zozlak/auth)

A simple yet flexible library for authenticating against different providers.

Currently supported authorization providers:

* HTTP basic
* HTTP digest
* user login and data fetched from HTTP headers (e.g. when set by Shibboleth)
* Google access_token
* fixed data (e.g. a fallback guest user)

Currently supported users database backends:

* PDO

## Usage

Simple example trying to authenticate with Google, then with HTTP basic and finally using a fixed 
`zzz` user as a fallback.

```php
namespace zozlak\auth;
require '/vendor/autoload.php';
$db = new usersDb\PdoDb('sqlite::memory:');

// init users
$db->putUser('aaa', authMethod\HttpBasic::pswdData('1234'));
$db->putUser('bbb', authMethod\HttpBasic::pswdData('1234'));

// create auth controller and add auth methods
// (comment/uncomment $ctl->addMethod() lines to test different combinations)
$ctl   = new AuthController($db);

$header = new TrustedHeader('HTTP_EPPN');
$ctl->addMethod($header);

$token = new GoogleToken(filter_input(INPUT_GET, 'token') ?? '');
$ctl->addMethod($token);

$shb = new Shibboleth('HTTP_EPPN', '', [], 'https://my.app/Shibboleth.sso/Login', 'https://my.app/url');
//$ctl->addMethod($shb, AuthController::ADVERTISE_ONCE);

$googleAppCfg = [
    'client_id' => 'appid.apps.googleusercontent.com',
    'client_secret' => 'appsecret',
    'redirect_uris' => ['https://my.app/url']
];
$googleAuthCfg = ['access_type' => 'offline', 'refresh_time' => 600];
$google = new Google(filter_input(INPUT_GET, 'token') ?? '', $googleAppCfg, $googleAuthCfg);
//$ctl->addMethod($google, AuthController::ADVERTISE_ONCE);

$basic = new HttpBasic('my realm');
$ctl->addMethod($basic, AuthController::ADVERTISE_ONCE);

$digest = new HttpDigest('realm');
//$ctl->addMethod($digest, AuthController::ADVERTISE_ONCE);

$guest = new Guest('zzz');
$ctl->addMethod($guest);

// try to authenticate
if ($ctl->authenticate()) {
    print_r([$ctl->getUserName(), $ctl->getUserData()]);
} else {
    // if not authenticated, advertise available method
    $ctl->advertise();
    header('HTTP/1.1 401 Unauthorized');
    echo "Authentication failed\n";
}
```

## Combining many authentication methods

Chaining many authentication methods is easy until it's only checking credentials provided by
a client in his request. 

The problem starts when request contains no (valid) credentials and we want to explicitely ask user 
to include them. The problem is in most cases **we can advertise only one auth method at once**. This is because 
different auth methods use conflicting advertisment mechanism, e.g.

* all OAuth2 (Google, etc.) and SAML (Shibboleth) methods use a `Location` header to redirect user
  to a login page and we can't return many redirects to different locations in one response
* presence of an HTTP Basic or HTTP Digest auth header in a response forces all GUI clients to prompt
  user for login and password and skip the rest of a response

Control over advertising auth methods is provided in the following way:

* You can assign each method in the chain one of three *advertisment levels*: 
    * `AuthMethod::ADVERTISE_NONE` auth method is never advertised
    * `AuthMethod::ADVERTISE_ONCE` auth method is advertised only if a request contained no
      credentials for this method (and if a request contained wrong credentials for this method,
      the method is not advertised again)
    * `AuthMethod::ADVERTISE_ALWAYS` auth method is always advertised
* When you call the `AutController::advertise()` method a first auth method in the chain which 
  fulfills its advertisment conditions is advertised.

You assigne the *advertisment level* when adding it to the auth chain using the second parameter 
of the `AutController::addMethod(AuthMethodInterface $method, int $advertise)` method.
**By default it's `AuthMethod::ADVERTISE_NONE`**

Remember `Guest`, `GoogleToken` and `TrustedHeaders` don't support advertisment.

### HTTP Digest method

HTTP Digest is difficult to combine with any other auth method. Unlike other methods the HTTP Digest
has to be advertised to the client before his request so he can prepare valid credentials. And once it is advertised
all GUI clients (most notably web browsers) will keep asking user for a login and password until valid ones are provided making it impossible to use any other authentication method.

(Poor) workarounds for this problem are:

* Putting HTTP Digest at the end of the auth chain allowing any other auth method to be checked first.
* Setting up HTTP Digest provider's advertise setting to `ADVERTISE_ONCE`. In such a case it will be advertised
  only when a client doesn't provide HTTP Digest credentials in his request and if credentials are
  provided (no matter if they are good or wrong) the HTTP Digest method won't be advertised again.
  It allows to resolve auth providers staying after the HTTP Digest in the auth chain at the cost of
  giving user only one chance to input a correct login and password.
