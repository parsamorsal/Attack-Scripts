import requests
import string
import base64
import sys


def get_flag(name):
    response = requests.get(
        "https://pacific-anchorage-60533.herokuapp.com/ce442?user=" + name)

    cookie = str(response.cookies)
    x = cookie.find("flag=") + 5
    y = cookie.find(" for")
    flag = cookie[x:y]

    if flag[0] == '"':
        return str.split(flag, '"')[1]
    else:
        return flag


def twoCharKey(key, size):
    two = []

    for i in string.ascii_letters:
        for j in string.ascii_letters:
            two.append(str(i) + str(j))

    for i in two:
        length = len(base64.b64decode(get_flag(key + i)))
        print(str(length) + ": " + key + i)
        if length <= size +1:
            key = key + i
            break

    return key


soFar = len(base64.b64decode(get_flag("flag:CES")))

key = "flag:CES"

while True:
    for i in string.ascii_letters:
        length = len(base64.b64decode(get_flag(key + i)))
        print(str(length) + ": " + key + i)
        if length <= soFar:
            key = key + i
            if len(key) == 9:
                key = twoCharKey(key, length)
                soFar = len(base64.b64decode(get_flag(key)))
                print(key)
            break
