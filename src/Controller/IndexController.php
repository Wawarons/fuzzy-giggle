<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;

class IndexController extends AbstractController {

    #[Route('/', name: 'index')]
    public function indexAction()
    {
        $user = $this->getUser();

        return $this->render('base.html.twig', [
            'user' => $user,
        ]);
    }
}
