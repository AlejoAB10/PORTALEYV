import bcrypt
password = "admin123".encode('utf-8')
hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
print(hashed)