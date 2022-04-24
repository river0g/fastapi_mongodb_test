import jwt
from fastapi import HTTPException
from passlib.context import CryptContext

from datetime import datetime, timedelta
from decouple import config

from typing import Tuple

JWT_KEY = config('JWT_KEY')


class AuthJwtCsrf():
    # fastapiが用意している認証周りのもの
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret_key = JWT_KEY

    # ユーザーが入力したパスワードをハッシュ化する。
    def generate_hashed_pw(self, password) -> str:
        return self.pwd_ctx.hash(password)

    # ユーザーが入力したパスワードと保存されているものが合致するか。
    def verify_pw(self, plain_pw, hashed_pw) -> bool:
        return self.pwd_ctx.verify(plain_pw, hashed_pw)

    def encode_jwt(self, email) -> str:
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=10),  # 有効期限
            'iat': datetime.utcnow(),  # 作成日時
            'sub': email  # ユーザーの情報を一意に識別できるもの
        }
        return jwt.encode(
            payload,
            self.secret_key,
            algorithm='HS256'
        )

    def decode_jwt(self, toke) -> str:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['sub']
        # トークンが失効しているエラー
        except jwt.ExpiredSignatureError:
            raise HTTPExcepiton(
                status_code=401, detail='The JWT has expired'
            )
        # 空のトークンが渡された時などに起こるエラー
        except jwt.InvalidTokenError as e:
            raise HTTPException(satatus_code=401, detail='JWT is not valid')

    def verify_jwt(self, request) -> str:
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(
                status_code=401, detail='No JWT exist: may not set yet or deleted'
            )

        # tokenは Bearer value と言う形になっているので、Bearer, ,を無視して代入するので以下のようになる。
        _, _, value = token.partition(" ")
        subject = self.decode_jwt(value)
        return subject

    def verify_update_jwt(self, request) -> Tuple[str, str]:
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token, subject

    def verify_csrf_update_jwt(self, request, csrf_protect, headers) -> str:
        csrf_token = csrf_protect.get_csrf_from_headers(headers)
        csrf_protect.validate_csrf(csrf_token)
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token
