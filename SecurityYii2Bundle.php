<?php

namespace maranqz\Bundle\SecurityYii2Bundle;

use maranqz\Bundle\SecurityYii2Bundle\DependencyInjection\Security\Factory\Yii2SessionFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class SecurityYii2Bundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new Yii2SessionFactory());
    }
}