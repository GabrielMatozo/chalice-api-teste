from chalice import Chalice

app = Chalice(app_name='chalice-api-teste')


@app.route('/')
def index():
    return {'hello': 'world'}
