<?php

namespace App\Security;

use Symfony\Bundle\SecurityBundle\Security;;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class  AuthenticationExtension extends AbstractExtension
{

    private Security $security;

    public function __construct (Security $security) {
        $this->security = $security;
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('current_user', [$this, 'getCurrentUser']),
        ];
    }

    public function getCurrentUser () {
        return $this->security->getUser();
    }

}
