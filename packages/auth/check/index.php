
<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;
require_once('../../../lib/auth.php');


function main(array $event): array
{
  return auth_check($event,'post');
}
