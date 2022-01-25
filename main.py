import json
from datetime import datetime, timedelta

from aiohttp import web
import jwt

class User:

    def __init__(self, id, email, password, is_admin):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin

    def __repr__(self):
        template = 'User id={s.id}: <{s.email}, is_admin={s.is_admin}>'
        return template.format(s=self)

    def __str__(self):
        return self.__repr__()

    def match_password(self, password):
        if password != self.password:
            raise User.PasswordDoesNotMatch

    class DoesNotExist(BaseException):
        pass

    class TooManyObjects(BaseException):
        pass

    class PasswordDoesNotMatch(BaseException):
        pass

    class objects:
        _storage = []
        _max_id = 0

        @classmethod
        def create(cls, email, password, is_admin=False):
            cls._max_id += 1
            cls._storage.append(User(cls._max_id, email, password, is_admin))

        @classmethod
        def all(cls):
            return cls._storage

        @classmethod
        def filter(cls, **kwargs):
            users = cls._storage
            for k, v in kwargs.items():
                if v:
                    users = [u for u in users if getattr(u, k, None) == v]
            return users

        @classmethod
        def get(cls, id=None, email=None):
            users = cls.filter(id=id, email=email)
            if len(users) > 1:
                raise User.TooManyObjects
            if len(users) == 0:
                raise User.DoesNotExist
            return users[0]


User.objects.create(email='user@email.com', password='password')

JWT_SECRET = 'SuPerUlTraSeCreTpswd'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 120

#wrapper aiohttp.web.response
def json_response(body='', **kwargs):
    kwargs['body'] = json.dumps(body or kwargs['body']).encode('utf-8')
    kwargs['content_type'] = 'text/json'
    return web.Response(**kwargs)


async def login(request):
    # получение данных из post запроса
    post_data = await request.post()

    try:
        # получение пользователя по почте из хранилища
        user = User.objects.get(email=post_data['email'])
        # проверка совпадения паролей
        user.match_password(post_data['password'])
    except (User.DoesNotExist, User.PasswordDoesNotMatch):
        # пользователя не существует / не совпадает пароль
        return json_response({'message': 'Wrong credentials'}, status=400)
    # создание полезной нагрузки токена
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    # enc
    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
    return json_response({'token': jwt_token.decode('utf-8')})

async def get_user(request):
    return json_response({'user': str(request.user)})


async def auth_middleware(app, handler):
    async def middleware(request):
        request.user = None
        # получаем токен из заголовка authorization
        jwt_token = request.headers.get('authorization', None)
        if jwt_token:
            try:
                # расшифруем его тем же алгоритмом, которым он был зашифрован
                payload = jwt.decode(jwt_token, JWT_SECRET,
                                     algorithms=[JWT_ALGORITHM])
            except (jwt.DecodeError, jwt.ExpiredSignatureError):
                # срок дейсвия токена истек / подпись не совпадает
                return json_response({'message': 'Token is invalid'},
                                     status=400)
            # если все ок, находим пользователя по id в payload
            request.user = User.objects.get(id=payload['user_id'])
        return await handler(request)
    return middleware

app = web.Application(middlewares=[auth_middleware])
app.router.add_route('GET', '/get-user', get_user)
app.router.add_route('POST', '/login', login)

