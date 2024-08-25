import vt

client = vt.Client("60aeb4e8da17028ecc1a1ea5f826bca9bbf91c674eac754ef7c83bc047ed3187")

user_url = input("URL: ")
url_id = vt.url_id(user_url)

# url_id = vt.url_id("http://www.virustotal.com")
print("URL Info: ")
# url = client.get_object("/urls/{}", url_id)
print("__________________________________________________________")
print("URL Scan: ")
analysis = client.scan_url(user_url)
print(analysis)

# url = "https://www.virustotal.com/api/v3/urls"

# headers = {
#     "accept": "application/json",
#     "content-type": "application/x-www-form-urlencoded",
#     "x-apikey": "60aeb4e8da17028ecc1a1ea5f826bca9bbf91c674eac754ef7c83bc047ed3187"
# }

# response = requests.post(url, headers=headers)

# print(response.text)
# print("finished...")