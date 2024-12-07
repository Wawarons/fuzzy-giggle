<?php

// src/Security/AppCustomAuthenticator.php
namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException as SymfonyAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class SecurityAuthenticator extends AbstractAuthenticator
{
    public function supports(Request $request): ?bool
    {
// Vérifie si la requête est pour le formulaire de connexion
        return $request->getPathInfo() === '/login' && $request->isMethod('POST');
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email');
        $password = $request->request->get('password');

// Validation et recherche de l'utilisateur
        $user = $this->getUserByEmail($email);

        if (!$user || !password_verify($password, $user->getPassword())) {
            throw new SymfonyAuthenticationException('Invalid credentials');
        }

        return new UsernamePasswordToken($user, 'main', $user->getRoles());
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException|SymfonyAuthenticationException $exception): ?Response
    {
// Redirige vers la page de connexion avec un message d'erreur
        $this->addFlash('error', 'Invalid credentials');
        return new RedirectResponse('/login');
    }

    public function onAuthenticationSuccess(Request $request, UsernamePasswordToken|TokenInterface $token, string $firewallName): ?Response
    {
// Redirige vers la page d'accueil après la connexion réussie
        return new RedirectResponse('/');
    }

    private function getUserByEmail(string $email): ?UserInterface
    {
// Cette méthode peut récupérer l'utilisateur depuis la base de données, par exemple avec Doctrine.
        return $this->userRepository->findOneByEmail($email);
    }
}
