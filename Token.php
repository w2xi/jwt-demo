<?php

require 'vendor/autoload.php';

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

class Token
{
    public static $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImZvbyI6ImJhciJ9.eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHA6XC9cL2V4YW1wbGUub3JnIiwianRpIjoiNGYxZzIzYTEyYWEiLCJpYXQiOjE2MTQzNTMzODYsIm5iZiI6MTYxNDM1MzQ0NiwiZXhwIjoxNjE0MzU2OTg2LCJ1aWQiOjF9.N9nD36BrK1kZCs8m0NDLh72IJ1fQW-SJVXHdTC6Xsi4';
    public static $config;
    public static $timezone = 'Asia/Shanghai';

    public function __construct()
    {
        // set timezone ( 设置时区 )
        ini_set('date.timezone', self::$timezone);
        // date_default_timezone_set(self::$timezone);
        self::$config = self::config();
    }
    public static function config()
    {
        $configuration = Configuration::forSymmetricSigner(
            // You may use any HMAC variations (256, 384, and 512)
            new Sha256(),
            // replace the value below with a key of your own!
            InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
            // You may also override the JOSE encoder/decoder if needed by providing extra arguments here
        );
        return $configuration;
    }
    /**
     * JWT ( JSON Web Token ) 由三部分组成:
     * header / payload / signature
     * header: { "alg": "HS256", "typ": "JWT" }
     * payload: { "sub": "subjetc: 1212", "iat": 1516239022 }
     * signature: "signature"
     */
    public function create()
    {
        $now    = new DateTimeImmutable('now', new DateTimeZone(self::$timezone));
        $token  = (new Builder())
        // Configures the issuer (iss claim)
        ->issuedBy('http://example.com')
        // Configures the audience (aud claim)
            ->permittedFor('http://example.org')
        // Configures the id (jti claim)
            ->identifiedBy('4f1g23a12aa')
        // Configures the time that the token was issue (iat claim)
            ->issuedAt($now)
        // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($now->modify('+1 minute'))
        // Configures the expiration time of the token (exp claim)
            ->expiresAt($now->modify('+1 hour'))
        // Configures a new claim, called "uid"
            ->withClaim('uid', 1)
        // Configures a new header, called "foo"
            ->withHeader('foo', 'bar')
        // Builds a new token
            ->getToken(self::$config->signer(), self::$config->signingKey());

        $headers = $token->headers(); // Retrieves the token headers
        $claims  = $token->claims(); // Retrieves the token claims
        // echo $token->headers()->get('foo'); // will print "bar"
        // echo $token->claims()->get('iss'); // will print "http://example.com"
        // echo $token->claims()->get('uid'); // will print "1"
        echo $token->toString(); // The string representation of the object is a JWT string
    }

    public function parse()
    {
    	$config = self::$config;
        assert($config instanceof Configuration);
        $token   = $config->parser()->parse('...');
        $headers = $token->headers();
        $claims  = $token->claims();

        return json_encode((array) $headers);
    }

    public function validate($token = null)
    {
        $clock  = new SystemClock(new DateTimeZone(self::$timezone));
        $config = self::$config;
        assert($config instanceof Configuration);

        $token = $config->parser()->parse($token ?: self::$token);
        assert($token instanceof Plain);

        $now = new DateTimeImmutable('now', new DateTimeZone(self::$timezone));
        // check if token expired
        if ($token->isExpired($now)) {
            die('The token is expired');
        }

        $headers = $token->getHeaders();
        $claims  = $token->getClaims();

        return json_encode((array) $token->claims());

        $config->setValidationConstraints(
            new Constraint\IdentifiedBy('4f1g23a12aa'),
            new Constraint\SignedWith($config->signer(), $config->verificationKey()),
            new Constraint\ValidAt($clock)
        );
        $constraints = $config->validationConstraints();
        try {
            $config->validator()->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            // list of constraints violation exceptions:
            var_dump($e->violations());
        }
    }

    public function JWTString()
    {
        // JWT consists of three parts separated by dots(.),
        // which are:
        // header / payload / signature
        // Therefore, a JWT typically looks like the following.
        // xxxxxx.yyyyyy.zzzzzz

        // $signature = new Sha256(base64_encode($header).'.'.base64_encode($payload), 'your secret');
        // $jwtString = base64_encode($header).'.'.base64_encode($payload).'.'.$signature;
    }
}


die(json_encode($_SERVER));


$jwt = new Token();

// create a jwt token 
echo $jwt->create();
echo '<br />';
