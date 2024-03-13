from flask import Flask, request, jsonify, Response, make_response, session
from db_reqs import *
import re
import bcrypt
from suka import app, salt
import jwt
from datetime import datetime, timedelta
from validation import *
import json


add_tables()


@app.route('/api/ping')
def ping():
    return jsonify({'status': 'ok'}), 200


@app.route('/api/countries')
def countries():
    arg = request.args.getlist('region')
    if arg == []:
        resp = make_response(get_countries())
    else:
        op = get_countries_by_region(arg)
        if op:
            resp = make_response(op)
        else:
            resp = make_response('{"reason": "Неверный регион страны"}', 400)
    resp.headers['Content-Type'] = 'application/json'
    return resp


@app.route('/api/countries/<alpha>')
def countriesArg(alpha):
    try:
        # raise Exception
        if alpha in get_alphas():
            resp = make_response(get_countries(alpha))
        else:
            resp = make_response('{"reason": "Неверный код страны"}', 404)
        resp.headers['Content-Type'] = 'application/json'
        return resp
    except Exception as E:
        resp = make_response('{"reason": "Неверный код страны"}', 404)
        resp.headers['Content-Type'] = 'application/json'
        return resp


@app.route('/api/countries/')
def countriesErr():
    resp = make_response('{"reason": "Неверный код страны"}', 404)
    resp.headers['Content-Type'] = 'application/json'
    return resp


@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        content = request.get_data()
        if check_for_json(content):
            content = json.loads(content)
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        if login_valid(content):
            resp = make_response('{"reason": "Логин не соответсвует требованиям"}', 400)
            resp.headers['Content-Type'] = 'application/json'
            return resp
        if email_valid(content):
            resp = make_response('{"reason": "Почта не соответсвует требованиям"}', 400)
            resp.headers['Content-Type'] = 'application/json'
            return resp
        if countryCode_valid(content):
            resp = make_response('{"reason": "Код страны не соответсвует требованиям"}', 400)
            resp.headers['Content-Type'] = 'application/json'
            return resp
        if isPublic_valid(content):
            resp = make_response('{"reason": "Поле isPublic не соответсвует требованиям"}', 400)
            resp.headers['Content-Type'] = 'application/json'
            return resp
        if password_valid(content):
            resp = make_response('{"reason": "Пароль не соответсвует требованиям"}', 400)
            resp.headers['Content-Type'] = 'application/json'
            return resp
        if 'phone' in content:
            if phone_valid(content):
                resp = make_response('{"reason": "Телефон не соответсвует требованиям"}', 400)
                resp.headers['Content-Type'] = 'application/json'
                return resp
        if 'image' in content:
            if image_valid(content):
                resp = make_response('{"reason": "Картинка не соответсвует требованиям"}', 400)
                resp.headers['Content-Type'] = 'application/json'
                return resp
        if 'phone' in content:
            if (get_user({'phone': content['phone']}) or get_user({'login': content['login']})
                    or get_user({'email': content['email']})):
                resp = make_response(
                    '{"reason": "Нарушено требование на уникальность авторизационных данных пользователей."}', 409)
                resp.headers['Content-Type'] = 'application/json'
                return resp
        else:
            content['phone'] = None
            if get_user({'email': content['email']}) or get_user({'login': content['login']}):
                resp = make_response(
                    '{"reason": "Нарушено требование на уникальность авторизационных данных пользователей."}', 409)
                resp.headers['Content-Type'] = 'application/json'
                return resp
        if 'image' not in content:
            content['image'] = None
        add_user(content)
        query = get_user({'login': content['login']})
        jsonn = profile_to_json(query)
        resp = make_response(jsonn, 201)
        resp.headers['Content-Type'] = 'application/json'
        return resp
    except Exception as E:
        return


@app.route('/api/auth/sign-in', methods=['POST'])
def sigh_in():
    content = request.get_data()
    if check_for_json(content):
        content = json.loads(content)
    else:
        return make_response({'reason': 'ne rabotaer'}, 400)
    if 'login' in content:
        login = content['login']
    else:
        return make_response({'reason': 'ne rabotaer'}, 400)
    if 'password' in content:
        password = content['password']
    else:
        return make_response({'reason': 'ne rabotaer'}, 400)
    user = get_user({'login': login})
    if not user:
        resp = make_response('{"reason": "Не найден пользователь с данным логином"}', 401)
        resp.headers['Content-type'] = 'application/json'
        return resp
    if bcrypt.checkpw(bytes(password, encoding='UTF-8'), bytes(user['pass_hash'], encoding='UTF-8')):
        session['logged_in'] = True
        token = jwt.encode({
                            'id': user['id'],
                            'user': login,
                            'pass_hash': user['pass_hash'],
                            'expiration': str(datetime.utcnow() + timedelta(seconds=3600))
                           }, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    else:
        resp = make_response('{"reason": "Неверный пароль"}', 401)
        resp.headers['Content-type'] = 'application/json'
    return resp


@app.route('/api/me/profile', methods=['GET', 'PATCH'])
def me_profile():
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['user']
        if request.method == 'PATCH':
            content = request.get_data()
            if check_for_json(content):
                content = json.loads(content)
            else:
                return make_response({'reason': 'ne rabotaer'}, 400)
            changes = []
            for i in content:
                flag = False
                if i == 'phone':
                    if not(phone_valid(content)):
                        if not(get_user({'phone': content[i]})):
                            flag = True
                        else:
                            resp = make_response('{"reason": "Пользователь с таким номером существует"}', 409)
                            resp.headers['Content-type'] = 'application/json'
                            return resp
                elif i == 'countryCode':
                    if not(countryCode_valid(content)):
                        flag = True
                elif i == 'isPublic':
                    if not(isPublic_valid(content)):
                        flag = True
                elif i == 'image':
                    if not(image_valid(content)):
                        flag = True
                if flag:
                    if i == 'isPublic':
                        changes.append(f'{i} = {str(content[i]).lower()}')
                    else:
                        changes.append(f'{i} = \'{content[i]}\'')
                else:
                    resp = make_response('{"reason": "Некорректные данные"}', 400)
                    resp.headers['Content-type'] = 'application/json'
                    return resp
            update_user(changes, login)
        user = get_user({'login': login})
        jsonn = broke_profile_to_json(user)
        resp = make_response(jsonn, 200)
        resp.headers['Content-type'] = 'application/json'
        return resp
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)


@app.route('/api/friends/add', methods=["POST"])
def add_friend():
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        content = request.get_data()
        if check_for_json(content):
            content = json.loads(content)
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        if 'login' in content:
            username_friend = content['login']
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        token = request.headers.get('Authorization').split()[1]
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if datetime.fromisoformat(decoded_token['expiration']) >= datetime.utcnow():
            login = decoded_token['user']
            if not(get_user({'login': username_friend})):
                return make_response({'reason': 'Пользователь с указанным логином не найден'}, 404)
            if username_friend == login or login in check_for_friend(username_friend):
                return make_response({'status': 'ok'}, 200)
            try:
                add_friend_to_db(username_friend, login)
                return make_response({'status': 'ok'}, 200)
            except:
                return Exception
    else:
        return make_response({"reason": "Недействительный токен"}, 401)


@app.route('/api/friends/remove', methods=['POST'])
def remove_friend():
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        content = request.get_data()
        if check_for_json(content):
            content = json.loads(content)
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        if 'login' in content:
            username_friend = content['login']
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if datetime.fromisoformat(decoded_token['expiration']) >= datetime.utcnow():
            login = decoded_token['user']
            if not(get_user({'login': username_friend})):
                return make_response({'reason': 'Пользователь с указанным логином не найден'}, 404)
            if username_friend == login or login not in check_for_friend(username_friend):
                return make_response({'status': 'ok'}, 200)
            try:
                remove_friend_from_db(username_friend, login)
                return make_response({'status': 'ok'}, 200)
            except:
                return Exception
    else:
        return make_response({"reason": "Недействительный токен"}, 401)


@app.route('/api/profiles/<username>')
def profiles(username):
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if datetime.fromisoformat(decoded_token['expiration']) >= datetime.utcnow():
            login = decoded_token['user']
            if not(get_user({'login': username})):
                return make_response({'reason': 'Пользователь с указанным логином не найден'}, 403)
            if get_user({'login': username})['ispublic'] or username in check_for_friend(login):
                resp = make_response(broke_profile_to_json(get_user({'login': username})), 200)
                resp.headers['Content-type'] = 'application/json'
                return resp
            else:
                return make_response({'reason': 'Пользователь с указанным логином не найден'}, 403)
    else:
        return make_response({"reason": "Токен умер"}, 401)


@app.route('/api/me/updatePassword', methods=['POST'])
def update_password():
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if datetime.fromisoformat(decoded_token['expiration']) >= datetime.utcnow():
            content = request.get_data()
            if check_for_json(content):
                content = json.loads(content)
            else:
                return make_response({'reason': 'ne rabotaer'}, 400)
            login = decoded_token['user']
            if 'oldPassword' in content:
                old_pass = content['oldPassword']
            else:
                return make_response({'reason': 'ne rabotaer'}, 400)
            pass_hash = decoded_token['pass_hash']
            if 'newPassword' in content:
                new_pass = content['newPassword']
            else:
                return make_response({'reason': 'ne rabotaer'}, 400)
            if bcrypt.checkpw(bytes(old_pass, encoding='UTF-8'), bytes(pass_hash, encoding='UTF-8')):
                if password_valid(new_pass):
                    update_user([f'pass_hash = \'{str(bcrypt.hashpw(bytes(new_pass, encoding="UTF-8"), salt))[2:-1]}\''], login)
                    return make_response({'status': 'ok'}, 200)
                else:
                    return make_response({'reason': 'Новый пароль не соответсвует требованиям'}, 400)
            else:
                return make_response({'reason': 'Старый пароль не совпадает с действительным'}, 403)
    else:
        return make_response({"reason": "Недействительный токен"}, 401)


@app.route('/api/friends')
def get_friends():
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        pass
        offset = 0
        if 'offset' in request.args:
            offset = request.args.get('offset')
        limit = 5
        if 'limit' in request.args:
            limit = request.args.get('limit')
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['user']
        resp = make_response(get_friends_from_db(login, offset, limit), 200)
        resp.headers['Content-type'] = 'application/json'
        return resp
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)


@app.route('/api/posts/new', methods=['POST'])
def add_post():
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['user']
        args = request.get_data()
        if check_for_json(args):
            args = json.loads(args)
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        if 'content' in args:
            content = args['content']
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        if 'tags' in args:
            tags = args['tags']
        else:
            return make_response({'reason': 'ne rabotaer'}, 400)
        resp = make_response(add_post_to_db(login, content, tags),200)
        resp.headers['Content-type'] = 'application/json'
        return resp
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)


@app.route('/api/posts/<uid>', methods=['GET'])
def get_post(uid):
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['user']
        try:
            post = json.loads(get_post_from_db(uid))
        except:
            return make_response({'reason': 'Указанный пост не найден либо к нему нет доступа.'}, 404)
        author = post['author']
        if get_user(author) and (author == login or get_user({'login': author})['ispublic'] or author in check_for_friend(login)):
            resp = make_response(get_post_from_db(uid))
            resp.headers['Content-type'] = 'application/json'
            return resp
        return make_response({'reason': 'Указанный пост не найден либо к нему нет доступа.'}, 404)
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)


@app.route('/api/posts/feed/my')
def get_my_posts():
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['user']
        offset = 0
        if 'offset' in request.args:
            offset = request.args.get('offset')
        limit = 5
        if 'limit' in request.args:
            limit = request.args.get('limit')
        resp = make_response(get_posts_with_author_from_db(login, offset, limit), 200)
        resp.headers['Content-type'] = 'application/json'
        return resp
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)


@app.route('/api/posts/feed/<author>')
def get_posts_with_author(author):
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['user']
        if get_user(author) and (get_user(author)['ispublic'] or author in check_for_friend(login)):
            offset = 0
            if 'offset' in request.args:
                offset = request.args.get('offset')
            limit = 5
            if 'limit' in request.args:
                limit = request.args.get('limit')
            resp = make_response(get_posts_with_author_from_db(login, offset, limit), 200)
            resp.headers['Content-type'] = 'application/json'
            return resp
        else:
            return make_response({'reason': 'Пользователь не найден либо к нему нет доступа.'}, 404)
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)


@app.route('/api/posts/<post_id>/like', methods=['POST'])
def set_like(post_id):
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['id']
        post = json.loads(get_post_from_db(post_id))
        if get_post_from_db(post_id) or (get_user(post['author'])['ispublic'] or post['author'] in check_for_friend(login)):
            set_like_in_db(login, post_id)
            resp = make_response(get_post_from_db(post_id))
            resp.headers['Content-type'] = 'application/json'
            return resp
        else:
            return make_response({'reason': 'Пост не найден'}, 404)
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)


@app.route('/api/posts/<post_id>/dislike', methods=['POST'])
def set_dislike(post_id):
    token = request.headers.get('Authorization').split()[1]
    if token_check(token):
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['id']
        if get_post_from_db(post_id):
            set_dislike_in_db(login, post_id)
            resp = make_response(get_post_from_db(post_id))
            resp.headers['Content-type'] = 'application/json'
            return resp
        else:
            return make_response({'reason': 'Пост не найден'}, 404)
    else:
        return make_response({'reason': 'Недействительный токен'}, 401)



if __name__ == '__main__':
    app.run(host=os.getenv('SERVER_ADDRESS'), port=int(os.getenv('SERVER_PORT')))
