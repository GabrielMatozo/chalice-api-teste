"""
API de autenticação com JWT no Chalice.
"""
from chalice import Chalice
import boto3
import bcrypt

app = Chalice(app_name='chalice-api-teste')


# Configuração do boto3 para acesso ao DynamoDB (armazenamento de usuários)
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # ajuste a região se necessário
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



# Endpoint raiz para teste de funcionamento da API de autenticação
@app.route('/')
def index():
    """Endpoint raiz para teste de funcionamento da API de autenticação."""
    return {'hello': 'world'}


# Endpoint de exemplo
@app.route('/pessoa')
def pessoa():
    """Retorna dados de exemplo de uma pessoa."""
    return {'nome': 'João', 'idade': 30}


# Endpoint de teste simples
@app.route('/teste')
def teste():
    """Endpoint de teste para retorno simples."""
    return {'retornoooooooo': 'teste'}
