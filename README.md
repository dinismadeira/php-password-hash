# Simple PHP Password and Hash Generator

Simple PHP Class to store passwords as hashes in a database.

By default it uses pbkdf2 to iterate a sha256 hash with a random salt.

## Usage

### Get the hash for a password

```php
// hash the password using sha256 iterated 2^10 times
$pass = new Pass($plainTextPass, 'sha256', 10);

// insert in the database
query("INSERT INTO `users` (`user`, `password_algorithm`, `password_iterations`, `password_salt`, `password_hash`) VALUES (
    '$user', '{$pass->getAlgo()}', {$pass->getIter()}, UNHEX('{$pass->getSalt()}'), UNHEX('{$pass->getHash()}')");
```

### Authenticate a user
```php
if (Pass::check($plainTextPass, $password_algorithm, $password_iterations, $password_salt, $password_hash)) {
  // login successful
}
```
