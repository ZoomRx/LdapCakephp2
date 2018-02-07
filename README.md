# Cakephp-ldap-auth plugin for CakePHP

## Requirements

* CakePHP 2.7+

## Installation

You can install this plugin into your CakePHP application using [composer](http://getcomposer.org).

The recommended way to install composer packages is:

```
composer require zoomrx/ldap-cakephp2
```

## Usage

In your app's `config/bootstrap.php` add:

```php
// In config/bootstrap.php
Plugin::load('LdapCakephp2');
```

## Configuration:

Copy ldap.php config to app/Config

Basic configuration for creating ldap handler instance

```php
    $config = [
        'host' => 'ldap.example.com',
        'port' => 389,
        'baseDn' => 'dc=example,dc=com',
        'startTLS' => true,
        'hideErrors' => true,
        'commonBindDn' => 'cn=readonly.user,ou=people,dc=example,dc=com',
        'commonBindPassword' => 'secret'
    ]
    $ldapHandler = new Ldap($config);
```

```php
    // In your controller, for e.g. app/Controller/AppController.php
    public function beforeFilter()
    {
        $this->Auth->authenticate = array(
            'LdapCakephp2.Ldap' => array(
                'fields' => array('username' => 'username','password'=>'password'),
                'scope' => array('User.type' => '1'),
            )
        );
    }
```

## Example:

Search for entry with cn starting with test
```php
    $ldapHandler->find('search', [
        'baseDn' => 'ou=people,dc=example,dc=com',
        'filter' => 'cn=test*',
        'attributes' => ['cn', 'sn', 'mail']
    ]);
```

Read a particular entry with cn=test.user
```php
    $ldapHandler->find('read', [
        'baseDn' => 'ou=people,dc=example,dc=com',
        'filter' => 'cn=test.user',
        'attributes' => ['cn', 'sn', 'mail']
    ]);
```

## TLS connections in development environment
    
    To connect an LDAP server over TLS connection, check ldap.conf file
    For mac, conf file is located in /usr/openldap/ldap.conf
    For unix, conf file is located in /etc/ldap/ldap.conf 
    To disable certificate verification change TLS_REQCERT to 'never' in ldap.conf file

