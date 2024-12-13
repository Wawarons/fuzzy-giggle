<?php

namespace App\Controller;
use App\Repository\CustomerRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\User\UserInterface;

class SettingsController extends AbstractController {

    private CustomerRepository $customerRepository;


    #[Route('/settings', name: 'settings')]
    public function index() {
        $user = $this->getUSer();

        if(!$user) {
            return $this->redirectToRoute('login');
        }
        return $this->render('settings/index.html.twig', [
            'user' => $user,
        ]);
    }

}