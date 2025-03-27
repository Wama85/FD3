from flask import Flask, request, jsonify, make_response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import sqlite3
import hashlib
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Configuración de la base de datos
def init_db():
    conn = sqlite3.connect('certificadora.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  salt TEXT NOT NULL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS claves
                 (user_id INTEGER NOT NULL,
                  private_key_pem TEXT NOT NULL,
                  public_key_pem TEXT NOT NULL,
                  FOREIGN KEY(user_id) REFERENCES usuarios(id))''')
    
    conn.commit()
    conn.close()

init_db()

# Decorador para requerir autenticación
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not verificar_usuario(auth.username, auth.password):
            return make_response('Could not verify', 401, 
                               {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated_function

# Funciones de ayuda para la base de datos
def crear_usuario(username, password):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    conn = sqlite3.connect('certificadora.db')
    c = conn.cursor()
    
    try:
        c.execute("INSERT INTO usuarios (username, password_hash, salt) VALUES (?, ?, ?)",
                 (username, password_hash, salt))
        user_id = c.lastrowid
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        c.execute("INSERT INTO claves (user_id, private_key_pem, public_key_pem) VALUES (?, ?, ?)",
                 (user_id, private_key_pem, public_key_pem))
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verificar_usuario(username, password):
    conn = sqlite3.connect('certificadora.db')
    c = conn.cursor()
    
    c.execute("SELECT password_hash, salt FROM usuarios WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return False
    
    stored_hash, salt = result
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    return password_hash == stored_hash

def obtener_clave_privada(username):
    conn = sqlite3.connect('certificadora.db')
    c = conn.cursor()
    
    c.execute('''SELECT private_key_pem FROM claves 
                 JOIN usuarios ON claves.user_id = usuarios.id 
                 WHERE username = ?''', (username,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return None
    
    return serialization.load_pem_private_key(
        result[0].encode(),
        password=None,
        backend=default_backend()
    )

# Rutas del servidor
@app.route('/verificar_credenciales', methods=['GET'])
@login_required
def verificar_credenciales():
    return jsonify({"mensaje": "Credenciales válidas"}), 200

@app.route('/registrar', methods=['POST'])
def registrar():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Se requieren username y password"}), 400
    
    if crear_usuario(data['username'], data['password']):
        return jsonify({"mensaje": "Usuario registrado exitosamente"}), 201
    else:
        return jsonify({"error": "El nombre de usuario ya existe"}), 400

@app.route('/firmar_con_password', methods=['POST'])
@login_required
def firmar_con_password():
    auth = request.authorization
    private_key = obtener_clave_privada(auth.username)
    
    if 'documento' not in request.files or 'doc_password' not in request.form:
        return jsonify({"error": "Se requieren documento y contraseña"}), 400
    
    archivo = request.files['documento']
    doc_password = request.form['doc_password']
    if archivo.filename == '':
        return jsonify({"error": "Nombre de archivo inválido"}), 400
    
    contenido = archivo.read()
    contenido_protegido = contenido + doc_password.encode()
    
    firma = private_key.sign(
        contenido_protegido,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    public_key = private_key.public_key()
    
    return jsonify({
        "nombre_archivo": archivo.filename,
        "documento": base64.b64encode(contenido).decode('utf-8'),
        "firma": base64.b64encode(firma).decode('utf-8'),
        "public_key": public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        "usuario": auth.username,
        "mensaje": "Firma generada con éxito"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
