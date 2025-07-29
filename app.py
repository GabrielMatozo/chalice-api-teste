


"""
API de autenticação com JWT no Chalice.
"""

import datetime
import secrets
from chalice import Chalice
import boto3
import bcrypt
import jwt



app = Chalice(app_name='chalice-api-teste')



# Configuração do boto3 para acesso ao DynamoDB (armazenamento de usuários)
# ajuste a região se necessário, contudo, estamos usando a região padrão
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
users_table = dynamodb.Table('Users')


# Configurações do JWT
JWT_SECRET = secrets.token_urlsafe(32)  # Chave secreta aleatória gerada a cada execução
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # 1 hora
# Função para extrair e validar o token JWT do header Authorization
def require_jwt_auth(request):
    """
    Extrai e valida o token JWT do header Authorization.
    Retorna o payload se válido, senão retorna erro 401.
    """
    auth_header = request.headers.get('authorization')
    if not auth_header or not auth_header.lower().startswith('bearer '):
        return None, {'error': 'Token JWT ausente ou inválido'}, 401
    token = auth_header.split(' ', 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload, None, 200
    except jwt.ExpiredSignatureError:
        return None, {'error': 'Token expirado'}, 401
    except jwt.InvalidTokenError:
        return None, {'error': 'Token inválido'}, 401


# Rota de login de usuário
@app.route('/login', methods=['POST'])
def login():
    """
    Endpoint de login: valida credenciais e retorna JWT se sucesso.
    """
    request = app.current_request
    data = request.json_body
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return {'error': 'username e password são obrigatórios'}, 400

    # Busca usuário no DynamoDB
    response = users_table.get_item(Key={'username': username})
    user = response.get('Item')
    if not user:
        return {'error': 'Usuário ou senha inválidos'}, 401

    # Valida senha
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return {'error': 'Usuário ou senha inválidos'}, 401

    # Gera token JWT
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {'token': token}

app = Chalice(app_name='chalice-api-teste')


# Configuração do boto3 para acesso ao DynamoDB (armazenamento de usuários)
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

users_table = dynamodb.Table('Users')



## Rota de cadastro de usuário (registro)
@app.route('/register', methods=['POST'])
def register_user():
    """
    Endpoint de registro de usuário para a API de autenticação JWT.
    Recebe username e password, verifica duplicidade, faz hash da senha e salva no DynamoDB.
    """
    request = app.current_request
    data = request.json_body
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return {'error': 'username e password são obrigatórios'}, 400

    # Verifica se usuário já existe no banco
    response = users_table.get_item(Key={'username': username})
    if 'Item' in response:
        return {'error': 'Usuário já existe'}, 409

    # Gera hash seguro da senha usando bcrypt
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Salva usuário com senha hasheada no DynamoDB
    users_table.put_item(Item={
        'username': username,
        'password': hashed.decode('utf-8')
    })
    return {'message': 'Usuário cadastrado com sucesso'}

# Proteger todas as rotas exceto /login e /register

@app.middleware('http')
def jwt_protect_all_routes(event, get_response):
    """Middleware que protege todas as rotas exceto /login e /register com JWT."""
    path = event.path
    # Permitir acesso livre apenas para login e registro
    if path in ['/login', '/register']:
        return get_response(event)
    # Proteger todas as outras rotas
    auth_header = event.headers.get('authorization')
    if not auth_header or not auth_header.lower().startswith('bearer '):
        return {'error': 'Token JWT ausente ou inválido'}, 401
    token = auth_header.split(' ', 1)[1]
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {'error': 'Token expirado'}, 401
    except jwt.InvalidTokenError:
        return {'error': 'Token inválido'}, 401
    return get_response(event)
