<?php

namespace maranqz\Bundle\SecurityYii2Bundle\User;

/**
 * Documentation {@see https://www.yiiframework.com/doc/api/2.0/yii-web-user}
 * Source {@see https://github.com/yiisoft/yii2/blob/master/framework/web/User.php}
 */
interface Yii2UserIdentityInterface
{
    /**
     * @return string|int
     */
    public function getId();

    /**
     * @return string
     * @see validateAuthKey()
     */
    public function getAuthKey();

    /**
     * @param string $authKey
     * @return bool
     * @see getAuthKey()
     */
    public function validateAuthKey($authKey);
}