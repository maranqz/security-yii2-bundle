<?php


namespace maranqz\Bundle\SecurityYii2Bundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class Yii2SessionFactory implements SecurityFactoryInterface
{
    const PREFIX_ID = 'security.authentication';
    const NAME_ID = 'yii2';

    protected $options = [
        'require_previous_session' => true,
    ];

    protected $defaultSuccessHandlerOptions = [];

    protected $defaultFailureHandlerOptions = [];

    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPointId)
    {
        // authentication provider
        $authProviderId = $this->createAuthProvider($container, $id, $config, $userProviderId);

        // authentication listener
        $listenerId = $this->createListener($container, $id, $config, $userProviderId);

        // create entry point if applicable (optional)
        $entryPointId = $this->createEntryPoint($container, $id, $config, $defaultEntryPointId);

        return [$authProviderId, $listenerId, $entryPointId];
    }

    public function getPosition()
    {
        return 'http';
    }

    public function getKey()
    {
        return 'yii2-session';
    }

    public function addConfiguration(NodeDefinition $node)
    {
        $builder = $node->children();

        $builder
            ->scalarNode('provider')->end()
            ->scalarNode('success_handler')->end()
            ->scalarNode('failure_handler')->end();

        foreach (array_merge($this->options, $this->defaultSuccessHandlerOptions,
            $this->defaultFailureHandlerOptions) as $name => $default) {
            if (is_bool($default)) {
                $builder->booleanNode($name)->defaultValue($default);
            } else {
                $builder->scalarNode($name)->defaultValue($default);
            }
        }
    }

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    { // authentication provider
        $provider = self::PREFIX_ID . '.provider.' . self::NAME_ID . '.' . $id;
        $container
            ->setDefinition($provider, new ChildDefinition(self::PREFIX_ID . '.provider.' . self::NAME_ID))
            ->replaceArgument(0, new Reference($userProviderId))->replaceArgument(
                1,
                new Reference('security.user_checker.' . $id)
            )
            ->replaceArgument(2, $id);

        return $provider;
    }

    protected function createListener($container, $id, $config, $userProvider)
    {
        $listenerId = $this->getListenerId();
        $listener = new ChildDefinition($listenerId);
        $listener->replaceArgument(3, $id);
        $listener->replaceArgument(4,
            new Reference($this->createAuthenticationSuccessHandler($container, $id, $config)));
        $listener->replaceArgument(5,
            new Reference($this->createAuthenticationFailureHandler($container, $id, $config)));
        $listener->replaceArgument(6, array_intersect_key($config, $this->options));

        $listenerId .= '.' . $id;
        $container->setDefinition($listenerId, $listener);

        return $listenerId;
    }

    protected function getListenerId()
    {
        return self::PREFIX_ID . '.listener.' . self::NAME_ID;
    }


    protected function createAuthenticationSuccessHandler($container, $id, $config)
    {
        $successHandlerId = $this->getSuccessHandlerId($id);
        $options = array_intersect_key($config, $this->defaultSuccessHandlerOptions);

        if (isset($config['success_handler'])) {
            $successHandler = $container->setDefinition($successHandlerId,
                new ChildDefinition(self::PREFIX_ID . '.custom_success_handler'));
            $successHandler->replaceArgument(0, new Reference($config['success_handler']));
            $successHandler->replaceArgument(1, $options);
            $successHandler->replaceArgument(2, $id);
        } else {
            $successHandler = $container->setDefinition($successHandlerId,
                new ChildDefinition(self::PREFIX_ID . '.success_handler'));
            $successHandler->addMethodCall('setOptions', [$options]);
            $successHandler->addMethodCall('setProviderKey', [$id]);
        }

        return $successHandlerId;
    }

    protected function createAuthenticationFailureHandler($container, $id, $config)
    {
        $id = $this->getFailureHandlerId($id);
        $options = array_intersect_key($config, $this->defaultFailureHandlerOptions);

        if (isset($config['failure_handler'])) {
            $failureHandler = $container->setDefinition($id,
                new ChildDefinition(self::PREFIX_ID . '.custom_failure_handler'));
            $failureHandler->replaceArgument(0, new Reference($config['failure_handler']));
            $failureHandler->replaceArgument(1, $options);
        } else {
            $failureHandler = $container->setDefinition($id,
                new ChildDefinition(self::PREFIX_ID . '.failure_handler'));
            $failureHandler->addMethodCall('setOptions', [$options]);
        }

        return $id;
    }

    protected function createEntryPoint($container, $id, $config, $defaultEntryPointId)
    {
        return $defaultEntryPointId;
    }

    protected function getSuccessHandlerId($id)
    {
        return self::PREFIX_ID . '.success_handler.' . $id . '.' . str_replace('-', '_', $this->getKey());
    }

    protected function getFailureHandlerId($id)
    {
        return self::PREFIX_ID . '.failure_handler.' . $id . '.' . str_replace('-', '_', $this->getKey());
    }
}
