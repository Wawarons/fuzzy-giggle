<?php

namespace App\Controller;

use App\Entity\Customer;
use App\Repository\CustomerRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\Validator\Constraints as Assert;

class AuthController extends AbstractController
{

    private CustomerRepository $customerRepository;
    private ValidatorInterface $validator;

    public function __construct(CustomerRepository $customerRepository, ValidatorInterface $validator)
    {
        $this->customerRepository = $customerRepository;
        $this->validator = $validator;
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
    public function registerUser(Request $request, EntityManagerInterface $entityManager, UserPasswordHasherInterface $passwordHasher): Response
    {
        $username = strtolower($request->request->get('username'));
        $email = strtolower($request->request->get('email'));
        $password = $request->request->get('password');
        $confirm_password = $request->request->get('confirm_password');

        $errors = $this->validator->validate($password, [
            new Assert\Regex([
                'pattern' => '/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-\.]).{8,}$/',
                'message' => 'Password must include uppercase, lowercase, number, and special character.'
            ]),
        ]);

        if(count($errors) > 0) {
            $this->addFlash('password', $errors[0]->getMessage());
            return $this->redirectToRoute('register');
        }


        //Validation inputs
        if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {

            //Check username not null
            if (empty($username)) {
                $this->addFlash('username', 'Username is required');
            }

            //Check email not null
            if (empty($email)) {
                $this->addFlash('email', 'Email is required');
            }

            //Check password not null
            if (empty($password)) {
                $this->addFlash('password', 'Password is required');
            }

            //Check confirm password not null
            if (empty($confirm_password)) {
                $this->addFlash('confirm_password', 'Confirm password is required');
            }

            return $this->redirectToRoute('register');
        }

        //Check if password and confirm password are equals
        if ($password != $confirm_password) {
            $this->addFlash('error', 'Passwords do not match');
            return $this->redirectToRoute('register');
        }
        //Check if email and username is already register
        $emailAlreadyExists = $this->customerRepository->findOneByEmail($email);
        $usernameAlreadyExists = $this->customerRepository->findOneByUsername($username);

        if ($emailAlreadyExists || $usernameAlreadyExists) {
            $emailAlreadyExists && $this->addFlash('email', "Email already register.");
            $usernameAlreadyExists && $this->addFlash('username', "Username already taken.");
            return $this->redirectToRoute('register');
        }


//Create new User
        $user = new Customer();
        $user->setUsername($username);
        $user->setEmail($email);
        $user->setPassword($passwordHasher->hashPassword($user, $password));

//push it to the database
        $entityManager->persist($user);
        $entityManager->flush();

//Redirect user to the login page
        return $this->redirectToRoute('login');
    }

    #[
        Route('/logout', name: 'logout')]
    public function logout(SessionInterface $session): Response
    {
        $session->clear();
        return $this->redirectToRoute('/');
    }
}