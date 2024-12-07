<?php

namespace App\Controller;

use App\Entity\Customer;
use App\Security\SecurityAuthenticator;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;

class AuthController extends AbstractController
{
    #[Route('/auth/login', name: 'login_post', methods: ['POST'])]
    public function loginUser(
        Request $request,
        EntityManagerInterface $entityManager,
        UserAuthenticatorInterface $userAuthenticator,
        SecurityAuthenticator $authenticator
    ): Response {
        $email = $request->request->get('email');
        $password = $request->request->get('password');

        // Récupérer l'utilisateur via Doctrine
        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user || !$this->isPasswordValid($user, $password)) {
            $this->addFlash('error', 'Invalid credentials.');
            return $this->redirectToRoute('login');
        }

        // Authentifier l'utilisateur
        return $userAuthenticator->authenticateUser($user, $authenticator, $request);
    }

    #[Route('/login', name: 'login')]
    public function login(): Response
    {
        return $this->render('security/auth.html.twig', [
            'type' => 'login'
        ]);
    }

    #[Route('/register', name: 'register')]
    public function register(): Response
    {
        return $this->render('security/auth.html.twig', [
            'type' => 'register'
        ]);
    }

    #[Route('/auth/register', name: 'register_post', methods: ['POST'])]
    public function registerUser(Request $request, EntityManagerInterface $entityManager): Response
    {
        $username = $request->request->get('username');
        $email = $request->request->get('email');
        $password = $request->request->get('password');
        $confirm_password = $request->request->get('confirm_password');


        if(empty($username) || empty($email) || empty($password) || empty($confirm_password)) {


            if (empty($username)) {
                $this->addFlash('error_input', "username");
                $this->addFlash('error', 'Username is required');
            }
            if (empty($email)) {
                $this->addFlash('error_input', "email");
                $this->addFlash('error', 'Email is required');
            }
            if (empty($password)) {
                $this->addFlash('error_input', "password");
                $this->addFlash('error', 'Password is required');
            }
            if (empty($confirm_password)) {
                $this->addFlash('error_input', "confirm_password");
                $this->addFlash('error', 'Confirm password is required');
            }

            return $this->redirectToRoute('register');
        }

        if($password != $confirm_password) {
            $this->addFlash('error', 'Passwords do not match');
            $this->addFlash('error_input', "password");
            $this->addFlash('error_input', "confirm_password");
            return $this->redirectToRoute('register');
        }

        $user = new Customer();
        $user->setUsername($username);
        $user->setEmail($email);
        $user->setPassword(password_hash($password, PASSWORD_DEFAULT));

        $entityManager->persist($user);
        $entityManager->flush();

        return $this->redirectToRoute('login');

    }
}