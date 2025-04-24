from sessions import Session
from models import User
from utils import Response, match_password, hash_password
from database import cursor, commit

session = Session()


@commit
def login(username: str, password: str):
    current_user: User | None = session.check_session()
    if current_user:
        return Response(message='Siz allaqachon tizimga kirgansiz', status_code=401)

    cursor.execute('SELECT * FROM users WHERE username = %s;', (username,))
    user_data = cursor.fetchone()

    if not user_data:
        return Response(message='Foydalanuvchi topilmadi', status_code=404)

    user = User.from_tuple(user_data)

    if user.login_try_count >= 5:
        return Response(message="Hisob bloklangan. Iltimos, admin bilan bog'laning.", status_code=403)

    if not match_password(password, user.password):
        cursor.execute(
            'UPDATE users SET login_try_count = login_try_count + 1 WHERE id = %s;',
            (user.user_id,)
        )
        return Response(message='Parol noto‘g‘ri', status_code=401)

  
    cursor.execute(
        'UPDATE users SET login_try_count = 0 WHERE id = %s;',
        (user.user_id,)
    )

    session.add_session(user)
    return Response(message='Tizimga muvaffaqiyatli kirildi ✅', status_code=200)


@commit
def register(username: str, password: str, email: str):
    current_user: User | None = session.check_session()
    if current_user:
        return Response(message='Siz allaqachon tizimga kirgansiz', status_code=401)

    
    cursor.execute('SELECT * FROM users WHERE username = %s;', (username,))
    if cursor.fetchone():
        return Response(message='Bu foydalanuvchi allaqachon mavjud', status_code=400)


    cursor.execute('SELECT * FROM users WHERE email = %s;', (email,))
    if cursor.fetchone():
        return Response(message='Bu email allaqachon ishlatilgan', status_code=400)

    hashed_password = hash_password(password)


    cursor.execute('''
        INSERT INTO users (username, password, email)
        VALUES (%s, %s, %s)
        RETURNING *;
    ''', (username, hashed_password, email))

    user_data = cursor.fetchone()
    user = User.from_tuple(user_data)

    session.add_session(user)
    return Response(message='Tizimga muvaffaqiyatli kirildi ✅', status_code=200)



if __name__ == "__main__":
    response = login('ADMIN', 'admin123')
    print(response.message)
