"""
API de autenticação com JWT no Chalice.
"""

import datetime
import logging
import secrets
import traceback

import bcrypt
import boto3
import jwt
from botocore.exceptions import ClientError
from chalice.app import Chalice

logger = logging.getLogger()
logger.setLevel(logging.INFO)

app = Chalice(app_name="chalice-api-teste")

# Configuração do boto3 para acesso ao DynamoDB (armazenamento de usuários)
dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
users_table = dynamodb.Table("Users")

# Configurações do JWT
JWT_SECRET = secrets.token_urlsafe(32)  # Gera uma chave aleatória a cada inicialização
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # 1 hora


# Função auxiliar para extrair e validar JWT
def get_jwt_payload(request):
    """Extrai e valida o token JWT do header Authorization."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None

    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# Middleware para proteger todas as rotas exceto /signin e /signup
@app.middleware("http")
def jwt_protect_all_routes(event, get_response):
    """Middleware que protege todas as rotas exceto /signin e /signup com JWT."""
    path = event.path

    # Permitir acesso livre apenas para signin e signup
    if path in ["/signin", "/signup"]:
        return get_response(event)

    # Proteger todas as outras rotas
    auth_header = event.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return {"error": "Token JWT ausente ou inválido"}, 401

    token = auth_header.split(" ", 1)[1]
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expirado"}, 401
    except jwt.InvalidTokenError:
        return {"error": "Token inválido"}, 401

    return get_response(event)


# Rota de cadastro de usuário (signup)
@app.route("/signup", methods=["POST"])
def signup():
    """
    Endpoint de registro de usuário para a API de autenticação JWT.
    Recebe username e password, verifica duplicidade, faz hash da senha e salva no DynamoDB.
    """
    try:
        request = app.current_request
        if request is None or not hasattr(request, "json_body"):
            return {"error": "Requisição inválida"}, 400
        data = request.json_body

        if not data:
            return {"error": "Dados JSON são obrigatórios"}, 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"error": "username e password são obrigatórios"}, 400

        # Validações básicas
        if len(username.strip()) < 3:
            return {"error": "Username deve ter pelo menos 3 caracteres"}, 400

        if len(password) < 6:
            return {"error": "Password deve ter pelo menos 6 caracteres"}, 400

        # Verifica se usuário já existe no banco
        response = users_table.get_item(Key={"username": username.strip()})
        if "Item" in response:
            return {"error": "Usuário já existe"}, 409

        # Gera hash seguro da senha usando bcrypt
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Salva usuário com senha hasheada no DynamoDB
        users_table.put_item(
            Item={
                "username": username.strip(),
                "password": hashed.decode("utf-8"),
                "created_at": datetime.datetime.utcnow().isoformat(),
            }
        )

        return {"message": "Usuário cadastrado com sucesso"}, 201

    except (ClientError, ValueError) as specific_error:
        logger.error("Erro específico no cadastro: %s", traceback.format_exc())
        return {"error": f"Erro no processamento: {str(specific_error)}"}, 400
    except Exception as general_error:  # pylint: disable=broad-exception-caught
        logger.error("Erro inesperado no cadastro: %s", traceback.format_exc())
        return {"error": f"Erro interno do servidor: {str(general_error)}"}, 500


# Rota de login de usuário (signin)
@app.route("/signin", methods=["POST"])
def signin():
    """
    Endpoint de login: valida credenciais e retorna JWT se sucesso.
    """
    try:
        request = app.current_request
        if request is None or not hasattr(request, "json_body"):
            return {"error": "Requisição inválida"}, 400
        data = request.json_body

        if not data:
            return {"error": "Dados JSON são obrigatórios"}, 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"error": "username e password são obrigatórios"}, 400

        # Busca usuário no DynamoDB
        response = users_table.get_item(Key={"username": username.strip()})
        user = response.get("Item")

        if not user:
            return {"error": "Usuário ou senha inválidos"}, 401

        # Valida senha
        stored_password = user["password"]
        if isinstance(stored_password, str):
            stored_password_bytes = stored_password.encode("utf-8")
        elif isinstance(stored_password, bytes):
            stored_password_bytes = stored_password
        else:
            return {"error": "Senha armazenada em formato inválido"}, 500

        if not bcrypt.checkpw(password.encode("utf-8"), stored_password_bytes):
            return {"error": "Usuário ou senha inválidos"}, 401

        # Gera token JWT
        payload = {
            "username": username.strip(),
            "exp": datetime.datetime.utcnow()
            + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS),
            "iat": datetime.datetime.utcnow(),
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        return {
            "token": token,
            "expires_in": JWT_EXP_DELTA_SECONDS,
            "token_type": "Bearer",
        }

    except (ClientError, ValueError) as specific_error:
        logger.error("Erro específico no login: %s", traceback.format_exc())
        return {"error": f"Erro no processamento: {str(specific_error)}"}, 400
    except Exception as general_error:  # pylint: disable=broad-exception-caught
        logger.error("Erro inesperado no login: %s", traceback.format_exc())
        return {"error": f"Erro interno do servidor: {str(general_error)}"}, 500


# Rota protegida /profile
@app.route("/profile", methods=["GET"])
def profile():
    """Endpoint protegido que retorna o nome do usuário extraído do JWT."""
    request = app.current_request

    # Extrai o payload JWT usando a função auxiliar
    payload = get_jwt_payload(request)
    if not payload:
        return {"error": "Token JWT inválido"}, 401

    return {
        "message": f"Olá, {payload['username']}!",
        "username": payload["username"],
        "token_expires_at": payload.get("exp"),
    }


# Rota de teste protegida adicional
@app.route("/protected", methods=["GET"])
def protected():
    """Rota de teste para verificar se a autenticação está funcionando."""
    request = app.current_request
    payload = get_jwt_payload(request)

    if not payload:
        return {"error": "Token JWT inválido"}, 401

    return {
        "message": "Acesso autorizado!",
        "user": payload["username"],
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }
