<?php

namespace maranqz\Bundle\SecurityYii2Bundle\User;

use Doctrine\Common\Persistence\ManagerRegistry;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

class Yii2UserProvider implements UserProviderInterface
{
    const DEFAULT_CONNECTION = 'yii2';

    /** @var EntityManagerInterface */
    private $entityManager;

    public function __construct(
        ManagerRegistry $registry,
        $connectionName = self::DEFAULT_CONNECTION
    ) {
        if (empty($connectionName)) {
            $connectionName = self::DEFAULT_CONNECTION;
        }

        $this->entityManager = $registry->getManager($connectionName);
    }

    public function loadUserByUsername($id)
    {
        $queryBuilder = $this->entityManager->createQueryBuilder()
            ->select('user')
            ->from(Yii2User::class, 'user')
            ->where('user.id = :id')->setParameter('id', trim($id))
            ->setMaxResults(1);

        $queryResponse = $queryBuilder->getQuery()->getResult();
        if (empty($queryResponse) || false == is_array($queryResponse)) {
            throw new UsernameNotFoundException(sprintf('Id "%s" does not exist in yii2 application.', $id));
        }

        return $queryResponse[0];
    }

    public function refreshUser(UserInterface $user)
    {
        if ($this->supportsClass(get_class($user))) {
            return $this->loadUserByUsername($user->getUsername());
        }

        throw new UnsupportedUserException('Invalid user type');
    }

    public function supportsClass($class)
    {
        return is_a($class, Yii2UserIdentityInterface::class, true);
    }
}
