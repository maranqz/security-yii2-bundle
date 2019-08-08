<?php


namespace maranqz\Bundle\SecurityYii2Bundle\User;


use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use BadMethodCallException;

class Yii2User implements Yii2UserIdentityInterface, UserInterface, EquatableInterface
{
    private $id;
    private $authKey;
    private $roles = [];

    public function getId()
    {
        return $this->id;
    }

    public function getAuthKey()
    {
        return $this->authKey;
    }

    public function validateAuthKey($authKey)
    {
        return $this->getAuthKey() === $authKey;
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function getPassword()
    {
        $this->notRealized(__METHOD__);
    }

    public function getSalt()
    {
        $this->notRealized(__METHOD__);
    }

    public function getUsername()
    {
        return strval($this->getId());
    }

    public function eraseCredentials()
    {
    }

    private function notRealized($methodName)
    {
        throw new BadMethodCallException('Method "' . $methodName . '"" not realized');
    }

    /**
     * @param UserInterface|Yii2UserIdentityInterface $user
     * @return $this|bool
     */
    public function isEqualTo(UserInterface $user)
    {
        return $this->getId() === $user->getId() && $this->getAuthKey() === $user->getAuthKey();
    }
}