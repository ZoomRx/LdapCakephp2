<?php

App::uses('Component', 'Controller');

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('ComponentCollection', 'Controller');
App::uses('CakeRequest', 'Network');
App::uses('CakeResponse', 'Network');

/**
 * LDAP authentication adapter for AuthComponent
 *
 * Provides LDAP authentication for given username and password
 *
 * ## usage
 * Add LDAP auth to controllers component
 */
class LdapAuthenticate extends BaseAuthenticate
{
    protected $ldap = null;

    /**
     * Constructor
     *
     * {@inheritDoc}
     */
    public function __construct(ComponentCollection $registry, array $config = [])
    {
        $this->_config = array_merge(Configure::read('Ldap'), $config);

        parent::__construct($registry, $config);
    }

    /**
     * Authenticate user
     *
     * {@inheritDoc}
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        if (empty($request->data['User']['username']) || empty($request->data['User']['password'])) {
            throw new LdapException('Empty username or password');
        }

        return $this->_findUser($request->data['User']['username'], $request->data['User']['password']);
    }

    /**
     * Find user method
     *
     * @param string $username Username
     * @param string $password Password
     * @return bool|array
     */
    public function _findUser($username, $password = null)
    {
        $this->ldap = new ldap($this->_config);
        $ldapUserDetails = $this->ldap->authenticateUser($username, $password);
        $this->ldap->close($this->_config);
        
        if (!$ldapUserDetails || empty($ldapUserDetails[0]['mail'][0])) {
            return false;
        }

        $userEmail = $ldapUserDetails[0]['mail'][0];

        $user = parent::_findUser(['email' => $userEmail]);

        //Handle the callback in User Model
        $callback = $this->_config['auth']['callback'] ?? '';
        if (!empty($callback) && empty($user)) {
            $user = ClassRegistry::init('User')->$callback($ldapUserDetails);
        }
        
        return $user;
    }
}
