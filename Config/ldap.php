<?php

/**
 * LDAP Configuration.
 *
 * Contains an array of settings to use for the LDAP configuration.
 *
 * To modify these parameters, copy this file into your own CakePHP APP/Config directory.
 *
 */


$config['Ldap'] = array(
    /*
     * - `host` - The domain controller hostname. This can be a closure or a string.
     *    The closure allows you to modify the rules in the configuration without the
     *    need to modify the LDAP plugin. One host (string) should be returned when
     *    using closure.
     * - `baseDN` - The base DN for directory
     * - `port` - The port to use. Default is 389 and is not required.
     * - `hideErrors` - flag to show/hide errors
     *    message. Set in session to Flash.ldap for flashing
     * - `startTls` - enable TLS
     * - `commonBindDn` - common bind Dn
     * - `commonBindPassword` - Common bind password
     * - `auth` - auth options
     */
    'enabled' => false,
    'syncInterval' => 12,
    'host' => 'localhost',
    'port' => 389,
    'baseDn' => 'dc=test,dc=com',
    'startTLS' => false,
    'hideErrors' => true,
    'commonBindDn' => 'cn=test.user,ou=people,dc=test,dc=com',
    'commonBindPassword' => 'test',
    'auth' => array(
        'searchFilter' => '(cn={username})',
        'bindDn' => 'cn={username},ou=people,dc=test,dc=com',
        'callback' => 'ldapAuthCallback'
    )
);
