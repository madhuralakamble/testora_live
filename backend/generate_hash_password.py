import bcrypt
password = 'superadmin123'  # Replace with your password string
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
print(hashed.decode('utf-8'))
