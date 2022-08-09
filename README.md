# Health Delivery - Pacote de Autorização

![GitHub repo size](https://img.shields.io/github/repo-size/HealthDelivery/core_auth?style=for-the-badge)
![GitHub language count](https://img.shields.io/github/languages/count/HealthDelivery/core_auth?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/HealthDelivery/core_auth?style=for-the-badge)
![Bitbucket open issues](https://img.shields.io/github/issues/HealthDelivery/core_auth?style=for-the-badge)

> Este projeto foi criado para implementar autorização utilizando JWT, para o ambiente do HealthDelivery utilizamos o SSO KeyCloak

## 💻 Pré-requisitos

Antes de começar, verifique se você atendeu aos seguintes requisitos:

* Visual Studio 2022 ou VSCode 
* .Net 6 
* Servidor Postgres para executar o serviço

## 🚀 Como utilizar o pacote

Depois de Baixado o Projeto

Após instalado utilizado nuget, configurar por appsettings ou variaveis de amnbiente as seguintes variaveis

* SSO_ISSUER = Url do emissor do Token
* SSO_PUBLIC_KEY = Chave publica gerada no SSO.
