<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\UserRepository;

class TokenAuthenticator extends AbstractGuardAuthenticator
{
    private $entityManager;
    private $userRepositiry;
    
    public function __construct(EntityManagerInterface $entityManager, UserRepository $userRepository){
        $this->entityManager=$entityManager;
        $this->userRepository=$userRepository;
        
    }
    
    
    public function supports(Request $request)
    {
        return $request->query->has("token");
    }

    public function getCredentials(Request $request)
    {
        $credentials=[
          "token"=>$request->query->get('token'),  
        ];
        return $credentials;
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
 {
    $user = $this->userRepository->findOneBy(['token' => $credentials['token'],]);
    
    if(!$user){
        throw new \Exception ("this token belongs to ");
    }
    return $user;
 }

    public function checkCredentials($credentials, UserInterface $user)
    {
        if($credentials['token']===$user->getToken()){
            $user->setToken('');
            $this->entityManager->persist($user);
            $this->entityManager->flush();
            return true;
        }
        return false;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new Response("yeeee");
    }
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return new Response ("You're logged in");
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        // todo
    }

    public function supportsRememberMe()
    {
        // todo
    }
}
