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
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # ajuste a região se necessário, contudo, estamos usando a região padrão
users_table = dynamodb.Table('Users')

# Configurações do JWT
JWT_SECRET = secrets.token_urlsafe(32)  # Chave secreta aleatória gerada a cada execução
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # 1 hora

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
