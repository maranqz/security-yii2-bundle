<?php

namespace maranqz\Bundle\SecurityYii2Bundle\Http\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Role\RoleInterface;
use InvalidArgumentException;

class Yii2SessionToken extends AbstractToken
{
    private $providerKey;

    /**
     * @param string|object $user The username (like a nickname, email address, etc.), or a UserInterface instance or an object implementing a __toString method
     * @param string $providerKey The provider key
     * @param RoleInterface[]|string[] $roles An array of roles
     *
     * @throws InvalidArgumentException
     */
    public function __construct($user, $providerKey, array $roles = [])
    {
        parent::__construct($roles);

        if (empty($providerKey)) {
            throw new InvalidArgumentException('$providerKey must not be empty.');
        }

        if (is_int($user)) {
            $user = strval($user);
        }

        $this->setUser($user);
        $this->providerKey = $providerKey;

        parent::setAuthenticated(\count($roles) > 0);
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated($isAuthenticated)
    {
        if ($isAuthenticated) {
            throw new \LogicException('Cannot set this token to trusted after instantiation.');
        }

        parent::setAuthenticated(false);
    }

    /**
     * Returns the provider key.
     *
     * @return string The provider key
     */
    public function getProviderKey()
    {
        return $this->providerKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        $serialized = [$this->providerKey, parent::serialize(true)];

        return $this->doSerialize($serialized, \func_num_args() ? func_get_arg(0) : null);
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list($this->providerKey, $parentStr) = \is_array($serialized) ? $serialized : unserialize($serialized);
        parent::unserialize($parentStr);
    }
}
