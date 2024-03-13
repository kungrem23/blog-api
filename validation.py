import re
from db_reqs import get_alphas

def login_valid(content):
    if not ('login' in content and re.fullmatch(r'[a-zA-Z0-9-]{1,30}', content['login'])):
        return True
    return False

def email_valid(content):
    if not ('email' in content and 1 <= len(content['email']) and len(content['email']) <= 50):
        return True
    return False

def countryCode_valid(content):
    if not ('countryCode' in content and content['countryCode'] in get_alphas()):
        return True
    return False

def isPublic_valid(content):
    if not ('isPublic' in content and type(content['isPublic']) is bool):
        return True
    return False

def password_valid(content):
    if not ('password' in content and len(content['password']) >= 6 and len(content['password']) <= 100
            and re.fullmatch(r'(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{6,100}', content['password'])):
        return True
    return False

def phone_valid(content):
    if not (re.fullmatch(r'\+[\d]{1,19}', content['phone'])):
        return True
    return False

def image_valid(content):
    if not (200 >= len(content['image']) and len(content['image']) >= 1):
        return True
    return False

