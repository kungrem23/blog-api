import psycopg2
import os
# from models import User
import bcrypt
import datetime
from suka import salt, app
from flask import request
import jwt
import uuid
import json
conn = psycopg2.connect(database=os.getenv('POSTGRES_DATABASE'), user=os.getenv('POSTGRES_USERNAME'), password=os.getenv('POSTGRES_PASSWORD'), host=os.getenv('POSTGRES_HOST'), port=os.getenv('POSTGRES_PORT'))


def get_regions():
    curs = conn.cursor()
    curs.execute('SELECT DISTINCT region FROM countries')
    resp = curs.fetchall()
    for i in range(len(resp)):
        resp[i] = resp[i][0]
    curs.close()
    return resp

def get_alphas():
    curs = conn.cursor()
    curs.execute('SELECT DISTINCT alpha2 FROM countries')
    resp = curs.fetchall()
    for i in range(len(resp)):
        resp[i] = resp[i][0]
    curs.close()
    return resp

def get_keys():
    curs = conn.cursor()
    curs.execute("SELECT column_name FROM information_schema.columns WHERE table_name='countries'")
    resp = curs.fetchall()
    for i in range(len(resp)):
        resp[i] = resp[i][0]
    curs.close()
    return resp

def get_countries(alpha=None):
    curs = conn.cursor()
    keys = get_keys()
    if alpha is None:
        curs.execute('SELECT row_to_json(countries) FROM countries')
        resp = sorted([i[0] for i in curs.fetchall()], key=lambda x: x['alpha2'])
        op = '[' + ', '.join(['{' + ', '.join([f'"{j}": "{i[j]}"' for j in keys[1:]]) + '}' for i in resp]) + ']'
    else:
        curs.execute(f"SELECT row_to_json(countries) FROM countries WHERE alpha2 = '{alpha}'")
        resp = curs.fetchall()
        op = '{' + ', '.join([f'"{j}": "{resp[0][0][j]}"' for j in keys[1:]]) + '}'
    curs.close()
    return op


def get_countries_by_region(arg):
    curs = conn.cursor()
    keys = get_keys()
    for i in arg:
        if i in get_regions():
            pass
        else:
            return False
    regions = ", ".join([f"'{i}'" for i in arg])
    curs.execute(f"SELECT row_to_json(countries) FROM COUNTRIES WHERE region = ANY (ARRAY[{regions}])")
    resp = curs.fetchall()
    op = '[' + ', '.join(['{' + ', '.join([f'"{j}": "{i[0][j]}"' for j in keys[1:]]) + '}' for i in resp]) + ']'
    curs.close()
    return op


def add_user(content):
    curs = conn.cursor()
    conn.commit()
    names = ['login', 'email', 'pass_hash', 'countryCode', 'isPublic', 'phone', 'image']
    names_content = ['login', 'email', 'password', 'countryCode', 'isPublic', 'phone', 'image']
    values = []
    for i in names_content:
        if i == 'isPublic':
            values.append("'" + str(content[i]).lower() + "'")
            continue
        if i == 'password':
            values.append("'" + str(bcrypt.hashpw(bytes(content[i], encoding='UTF-8'), salt))[2:-1] + "'")
            continue
        if content[i] is None:
            values.append('Null')
            continue
        values.append("'" + content[i] + "'")
    curs.execute(f"INSERT INTO users ({', '.join(names)}) VALUES ({', '.join(values)})")
    conn.commit()
    curs.close()


def get_user(arg):
    curs = conn.cursor()
    curs.execute(f"SELECT row_to_json(users) FROM users WHERE {list(arg.keys())[0]} = '{arg[list(arg.keys())[0]]}'")
    try:
        resp = curs.fetchall()[0][0]
    except:
        resp = []
    curs.close()
    return resp

def add_tables():
    curs = conn.cursor()
    curs.execute('''CREATE TABLE IF NOT EXISTS users(
                        id SERIAL PRIMARY KEY,
                        login TEXT NOT NULL UNIQUE,
                        pass_hash TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        countryCode TEXT NOT NULL,
                        isPublic BOOL NOT NULL,
                        phone TEXT UNIQUE,
                        image TEXT
                    );
                    
                    CREATE TABLE IF NOT EXISTS friends(
                        id serial primary key,
                        login text,
                        friend TEXT,
                        addedAt TEXT
                    );
                    
                    CREATE TABLE IF NOT EXISTS posts(
                        id TEXT primary key,
                        content TEXT,
                        author TEXT,
                        tags TEXT[],
                        createdAt TEXT,
                        likesCount INTEGER,
                        dislikesCount INTEGER
                    );
                    
                    CREATE TABLE IF NOT EXISTS likes(
                        id SERIAL PRIMARY KEY,
                        post_id TEXT REFERENCES posts(id),
                        user_id INTEGER REFERENCES users(id),
						islike BOOLEAN
                    );
                    ''')
    conn.commit()
    curs.close()


def profile_to_json(query):
    keys = ['login', 'email', 'countryCode', 'isPublic', 'phone', 'image']
    jsonn = '{\"profile\":{'
    a = []
    for i in keys:
        if query[i.lower()] is not None:
            if i == 'isPublic':
                a.append(f'"{i}": {str(query[i.lower()]).lower()}')
            else:
                a.append(f'"{i}": "{query[i.lower()]}"')
    jsonn += ', '.join(a)
    jsonn += '}}'
    return jsonn

def broke_profile_to_json(query):
    keys = ['login', 'email', 'countryCode', 'isPublic', 'phone', 'image']
    jsonn = '{'
    a = []
    # jsonn += ', '.join([f"\"{i}\": \"{query[i]}\"" for i in keys if query[i] is not None])
    for i in keys:
        if query[i.lower()] is not None:
            if i == 'isPublic':
                a.append(f'"{i}": {str(query[i.lower()]).lower()}')
            else:
                a.append(f'"{i}": "{query[i.lower()]}"')
    jsonn += ', '.join(a)
    jsonn += '}'
    return jsonn

# def add_user_model(content):
#     if 'phone' not in content:
#         content['phone'] = None
#     if 'image' not in content:
#         content['image'] = None
#     new_user = User(login=content['login'],
#                     pass_hash=str(bcrypt.hashpw(bytes(content['password'], encoding='UTF-8'), salt))[2:-1],
#                     email=content['email'], countrycode=content['countryCode'], ispublic=content['isPublic'],
#                     phone=content['phone'], image=content['image'])
#     db.session.add(new_user)
#     db.session.commit()

def update_user(changes, login):
    curs = conn.cursor()
    curs.execute(f'UPDATE users SET {", ".join(changes)} WHERE login = \'{login}\'')
    conn.commit()
    curs.close()

def check_for_friend(login):
    curs = conn.cursor()
    curs.execute(f'SELECT friend FROM friends WHERE login = \'{login}\'')
    resp = curs.fetchall()
    op = []
    for i in resp:
        op.append(i[0])
    curs.close()
    return op

def add_friend_to_db(friend, login):
    curs = conn.cursor()
    curs.execute(f'INSERT INTO friends (login, friend, addedAt) VALUES (\'{friend}\', \'{login}\', '
                 f'\'{datetime.datetime.utcnow().isoformat("T")}\')')
    conn.commit()
    curs.close()

def remove_friend_from_db(friend, login):
    curs = conn.cursor()
    curs.execute(f'DELETE FROM friends WHERE login = \'{friend}\' and friend = \'{login}\'')
    conn.commit()
    curs.close()

def token_check(token):
    try:
        token = request.headers.get('Authorization').split()[1]
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        login = decoded_token['user']
        if (datetime.datetime.fromisoformat(decoded_token['expiration']) >= datetime.datetime.utcnow() and
                decoded_token['pass_hash'] == get_user({'login': login})['pass_hash']):
            return True
        else:
            return False
    except:
        return False

def get_friends_from_db(login, offset, limit):
    curs = conn.cursor()
    curs.execute(f'SELECT login, addedat FROM friends WHERE friend = \'{login}\' OFFSET {offset} LIMIT {limit}')
    resp = curs.fetchall()
    op = "["
    a = []
    for i in resp:
        a.append('{' + f'"login": "{i[0]}", "addedAt": "{i[1]}"' + '}')
    op += ", ".join(a)
    op += "]"
    curs.close()
    return op

def add_post_to_db(login, content, tags):
    curs = conn.cursor()
    uid = uuid.uuid1()
    # taggs = '["' + '", "'.join(tags) + '"]'
    curs.execute(f'INSERT INTO posts (id, author, content, tags, likescount, dislikescount, createdAt) '
                 f'VALUES (\'{uid}\', \'{login}\', \'{content}\', ARRAY{tags}, 0, 0, '
                 f'\'{datetime.datetime.utcnow().isoformat("T")}\')')
    conn.commit()
    curs.close()
    return get_post_from_db(uid)

def get_post_from_db(uid):
    curs = conn.cursor()
    keys = ['id', 'content', 'author', 'tags', 'createdAt', 'likesCount', 'dislikesCount']
    curs.execute(f'SELECT row_to_json(posts) FROM posts WHERE id = \'{uid}\'')
    resp = curs.fetchall()
    try:
        resp = resp[0][0]
        op = '{'
        a = []
        for i in keys:
            if i in ['likesCount', 'dislikesCount']:
                a.append(f'"{i}": {resp[i.lower()]}')
                continue
            if i == 'tags':
                b = '[' + ', '.join([f'"{j}"' for j in resp[i.lower()]]) + ']'
                a.append(f'"{i}": {b}')
            a.append(f'"{i}": "{resp[i.lower()]}"')
        op += ', '.join(a)
        op += '}'
    except:
        op = []
    curs.close()
    return op

def get_posts_with_author_from_db(author, offset, limit):
    curs = conn.cursor()
    curs.execute(f'SELECT row_to_json(posts) FROM posts WHERE author = \'{author}\' OFFSET {offset} LIMIT {limit}')
    resp = curs.fetchall()
    keys = ['id', 'content', 'author', 'tags', 'createdAt', '']
    op = '['
    a = []
    for i in resp:
        a.append(get_post_from_db(i[0]['id']))
    op += ', '.join(a)
    op += ']'
    curs.close()
    return op

def get_is_like(login, post_id):
    curs = conn.cursor()
    curs.execute(f'SELECT row_to_json(likes) FROM likes WHERE user_id = {login} AND post_id = \'{post_id}\'')
    resp = curs.fetchall()
    if resp:
        return resp[0][0]
    else:
        return False


def set_like_in_db(login, post_id):
    curs = conn.cursor()
    like = get_is_like(login, post_id)
    post = json.loads(get_post_from_db(post_id))
    if like:
        if not(like['islike']):
            curs.execute(f'UPDATE likes SET islike = true WHERE user_id = \'{login}\' AND post_id = \'{post_id}\'')
            curs.execute(f'UPDATE posts SET dislikescount = {post["dislikesCount"] - 1} WHERE id = \'{post_id}\'')
            curs.execute(f'UPDATE posts SET likescount = {post["likesCount"] + 1} WHERE id = \'{post_id}\'')
    else:
        curs.execute(f'INSERT INTO likes (post_id, user_id, islike) VALUES(\'{post_id}\', \'{login}\', true)')
        curs.execute(f'UPDATE posts SET likescount = {post["likesCount"] + 1} WHERE id = \'{post_id}\'')
    conn.commit()
    curs.close()


def set_dislike_in_db(login, post_id):
    curs = conn.cursor()
    like = get_is_like(login, post_id)
    post = json.loads(get_post_from_db(post_id))
    if like:
        if like['islike']:
            curs.execute(f'UPDATE likes SET islike = false WHERE user_id = \'{login}\' AND post_id = \'{post_id}\'')
            curs.execute(f'UPDATE posts SET likescount = {post["likesCount"] - 1} WHERE id = \'{post_id}\'')
            curs.execute(f'UPDATE posts SET dislikescount = {post["dislikesCount"] + 1} WHERE id = \'{post_id}\'')
    else:
        curs.execute(f'INSERT INTO likes (post_id, user_id, islike) VALUES(\'{post_id}\', \'{login}\', false)')
        curs.execute(f'UPDATE posts SET dislikescount = {post["dislikesCount"] + 1} WHERE id = \'{post_id}\'')
    conn.commit()
    curs.close()


def check_for_json(content):
    try:
        a = json.loads(content)
        return True
    except:
        return False
