from sessions import Session
from models import User
from utils import Response, match_password
from database import cursor, commit

session = Session()

@commit
def login(username: str, password: str):
    current_user: User | None = session.check_session()
    if current_user:
        return Response(message='siz allaqachon tizimga kirgansiz', status_code=401)

    get_user_by_username_query = '''
        SELECT * FROM users WHERE username = %s;
    '''
    data = (username,)
    cursor.execute(get_user_by_username_query, data)
    user_data = cursor.fetchone()

    if not user_data:
        return Response(message='foydalanuvchi topilmadi', status_code=404)

    user = User.from_tuple(user_data)

    if user.login_try_count >= 5:
        return Response(message="Hisob bloklangan. Iltimos, admin bilan bog'laning.", status_code=403)

    if not match_password(password, user.password):
        update_login_try_count_field = '''
            UPDATE users SET login_try_count = login_try_count + 1 WHERE id = %s;
        '''
        cursor.execute(update_login_try_count_field, (user.user_id,))
        return Response(message='Pparol noto‘g‘ri', status_code=401)


    reset_login_try_count = '''
        UPDATE users SET login_try_count = 0 WHERE id = %s;
    '''
    cursor.execute(reset_login_try_count, (user.user_id,))

    session.add_session(user)
    return Response(message='Tizimga muvaffaqiyatli kirildi ✅')


if __name__ == "__main__":
    response = login('ADMIN', 'admin123')
    print(response.message)
