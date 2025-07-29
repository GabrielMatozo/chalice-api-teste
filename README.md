# Chalice API de Autenticação JWT

API de autenticação simples usando AWS Chalice, DynamoDB, JWT e bcrypt.

## Funcionalidades
- Cadastro de usuário (/signup)
- Login com geração de token JWT (/signin)
- Rotas protegidas por JWT (exemplo: /profile)
- Senhas protegidas com bcrypt
- Armazenamento de usuários no DynamoDB

## Pré-requisitos
- Python
- AWS CLI configurado (com credenciais válidas)
- DynamoDB com tabela `Users` (chave primária: `username`)

## Instalação

```bash
# Clone o repositório
$ git clone <url-do-repo>
$ cd chalice-api-teste

# (Opcional) Crie e ative um ambiente virtual
$ python -m venv venv
$ .\venv\Scripts\activate  # Windows

# Instale as dependências
$ pip install -r requirements.txt

# Instale o Chalice globalmente, se não tiver
$ pip install chalice
```

## Configuração AWS
- Configure suas credenciais AWS (ex: `aws configure`)
- Crie a tabela DynamoDB chamada `Users` com chave primária `username` (String)


## Executando Localmente

```bash
# Inicie o servidor local do Chalice
$ chalice local
```

A API estará disponível em http://localhost:8000

## Testando o Fluxo

### 1. Cadastro de Usuário

```
POST /signup
Content-Type: application/json
{
  "username": "usuario1",
  "password": "senha123"
}
```
Resposta esperada:
```
{
  "message": "Usuário cadastrado com sucesso"
}
```

### 2. Login

```
POST /signin
Content-Type: application/json
{
  "username": "usuario1",
  "password": "senha123"
}
```
Resposta esperada:
```
{
  "token": "<JWT>"
}
```

### 3. Acesso a rota protegida

```
GET /profile
Authorization: Bearer <JWT>
```
Resposta esperada:
```
{
  "mensagem": "Olá, usuario1!"
}
```
Se o token for inválido ou ausente:
```
{
  "error": "Token JWT ausente ou inválido"
}
```

## Observações
- O segredo JWT é gerado aleatoriamente a cada inicialização do app. Após reiniciar, tokens antigos deixam de ser válidos.
- Em produção, utilize um segredo fixo e seguro para o JWT.
- O projeto já está pronto para deploy no AWS Lambda via `chalice deploy`.

---

Feito com ❤️ usando Chalice, DynamoDB, JWT e bcrypt.
