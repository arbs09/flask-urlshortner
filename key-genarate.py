import secrets
import string

key_length = 32

random_key = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(key_length))

print(random_key)