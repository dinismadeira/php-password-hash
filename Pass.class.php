<?php
/**
 * Compute the hash for a password
 *
 * Get the hash for a new password in order to store it in a database.
 * Check a given password against a hash (authentication).
 * Generate random passwords.
 */
class Pass {
  const TRIM_PASS_LEN = 1024; // trim the passwords to this length in order to avoid DOS attacks
  const ALGO = 'sha256';
  const ITER = 15; // number of iterations as 2^n
  const PASS_LEN = 32; // generated password length
  const SALT_LEN = 32; // generated salt length (bytes)
  const HASH_LEN = 32; // generated hash length (bytes)
  const SITE_SALT = ''; //fixed part of salt (hexadecimal string)
  
  private $pass;
  private $algo;
  private $iter;
  private $salt;
  private $hash;
  
  static public function randStr($len, $chars = 'A-Za-z0-9\s') {
    $chars = str_replace(
      array('A-Z','a-z','0-9', '\s', 'a-f'),
      array('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz', '0123456789', '!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~', 'abcdef'), $chars);
    $charsLen = strlen($chars) - 1;
    $str = "";
    for ($i = 0; $i < $len; $i++) $str .= $chars[mt_rand(0, $charsLen)];
    return $str;
  }
  
  /**
   * Generate a random password.
   */
  static public function createPass($len = self::PASS_LEN, $chars = 'A-Za-z0-9\s') {
    return self::randStr($len, $chars);
  }
  
  
  static public function hash($pass, $algo = self::ALGO, $iter = self::ITER) {
    return array(
      $algo,
      $iter,
      $salt = self::randStr(self::SALT_LEN * 2, '0-9a-f'),
      self::pbkdf2($algo, $pass, pack("H*", self::SITE_SALT.$salt), pow(2, $iter), self::HASH_LEN));
  }
  
  /**
   * Check a password against a hash
   */
  static public function check($pass, $algo, $iter, $salt, $hash) {
    //if (!$algo) throw new Exception("unknown algo");
    return self::equals($hash, self::pbkdf2($algo, substr($pass, 0, self::TRIM_PASS_LEN), pack("H*", self::SITE_SALT.$salt), pow(2, $iter), self::HASH_LEN));
  }

  // Compare two strings $a and $b in length-constant time.
  static public function equals($a, $b) {
    $diff = strlen($a) ^ strlen($b);
    for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
      $diff |= ord($a[$i]) ^ ord($b[$i]);
    }
    return $diff === 0; 
  }

  static public function pbkdf2($algorithm, $password, $salt, $count, $key_length = 0, $raw_output = false) {
    $algorithm = strtolower($algorithm);
    if (!in_array($algorithm, hash_algos(), true)) trigger_error('PBKDF2 ERROR: Invalid hash algorithm. ('.$algorithm.')', E_USER_ERROR);
    if ($count <= 0 || $key_length < 0) trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);
    
    if (function_exists("hash_pbkdf2")) {
      return hash_pbkdf2($algorithm, $password, $salt, $count, $raw_output ? $key_length :  $key_length * 2, $raw_output);
    }
    
    $hash_length = strlen(hash($algorithm, "", true));
    $block_count = $key_length ? ceil($key_length / $hash_length) : $hash_length;
    
    $output = "";
    for ($i = 1; $i <= $block_count; $i++) {
      // $i encoded as 4 bytes, big endian.
      $last = $salt . pack("N", $i);
      // first iteration
      $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
      // perform the other $count - 1 iterations
      for ($j = 1; $j < $count; $j++) {
        $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
      }
      $output .= $xorsum;
    }
    return $raw_output ?
      ($key_length ? substr($output, 0, $key_length) : $output) :
      bin2hex($key_length ? substr($output, 0, $key_length) : $output);
  }
  
  // Get the password in plain text
  public function getPass() { return $this->pass; }
  
  // Get the algorithm used to generate the hash
  public function getAlgo() { return $this->algo; }
  
  // Get the 2^n power for the number of iteratinos
  public function getIter() { return $this->iter; }
  
  // Get the salt used to generate the hash
  public function getSalt() { return $this->salt; }
  
  // Get the hash
  public function getHash() { return $this->hash; }
  
  function Pass($pass = false, $algo = self::ALGO, $iter = self::ITER) {
    $this->pass = $pass === false ? self::createPass() : $pass;
    $hash = self::hash($this->pass, $algo, $iter);
    $this->algo = $hash[0];
    $this->iter = $hash[1];
    $this->salt = $hash[2];
    $this->hash = $hash[3];
  }
}
