<?php

namespace App\Security;

use App\Entity\Customer;
use App\Repository\CustomerRepository;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException as SymfonyAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

class SecurityAuthenticator extends AbstractAuthenticator
{
    private CustomerRepository $customerRepository;
    private RequestStack $requestStack;
    public function __construct(CustomerRepository $customerRepository, RequestStack $requestStack)
    {
        $this->customerRepository = $customerRepository;
        $this->requestStack = $requestStack;
    }

    public function supports(Request $request): ?bool
    {
        return $request->getPathInfo() === '/login' && $request->isMethod('POST');
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('_username');
        $password = $request->request->get('_password');

        $user = $this->getUserByEmail($email);

        if (!$user || !password_verify($password, $user->getPassword())) {
            throw new SymfonyAuthenticationException('Invalid credentials');
        }

        return new Passport(new UserBadge($user->getEmail()), new PasswordCredentials($password));
    }

    public function onAuthenticationFailure(Request $request, SymfonyAuthenticationException $exception): ?RedirectResponse
    {
        $session = $this->requestStack->getSession();
        $session->getFlashBag()->add('login_error', "Authentication failed");
        return new RedirectResponse('/login');
    }

    public function onAuthenticationSuccess(Request $request, UsernamePasswordToken|TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse('/');
    }

    private function getUserByEmail(string $email): ?Customer
    {
        return $this->customerRepository->findOneByEmail($email);
    }
}
