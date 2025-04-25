from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import pyodbc
import bcrypt
import csv
from io import StringIO
import re
import os

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# Portal database configuration (PORTAL_EYV)
PORTAL_DB_CONFIG = {
    'server': os.getenv('PORTAL_DB_SERVER', '192.168.1.40'),
    'database': os.getenv('PORTAL_DB_DATABASE', 'PORTAL_EYV'),
    'trusted_connection': os.getenv('PORTAL_DB_TRUSTED', 'yes'),
    'driver': os.getenv('PORTAL_DB_DRIVER', 'ODBC Driver 17 for SQL Server')
}

# Editor de BD database configuration (Pruebas)
EDITOR_DB_CONFIG = {
    'server': os.getenv('EDITOR_DB_SERVER', '192.168.1.40'),
    'instance': os.getenv('EDITOR_DB_INSTANCE', 'WIMPOS'),
    'database': os.getenv('EDITOR_DB_DATABASE', 'Pruebas'),
    'username': os.getenv('EDITOR_DB_USERNAME', 'sa'),
    'password': os.getenv('EDITOR_DB_PASSWORD', 'CIEV2011ev'),
    'driver': os.getenv('EDITOR_DB_DRIVER', 'ODBC Driver 17 for SQL Server')
}

# Database Connector for Portal (Windows Authentication)
class PortalDatabaseConnector:
    def __init__(self, server, database, trusted_connection, driver):
        self.server = server
        self.database = database
        self.trusted_connection = trusted_connection
        self.driver = driver
        self.connection = None
        self.cursor = None
    
    def connect(self):
        try:
            connection_string = (
                f"DRIVER={{{self.driver}}};"
                f"SERVER={self.server};"
                f"DATABASE={self.database};"
                f"Trusted_Connection={self.trusted_connection};"
            )
            self.connection = pyodbc.connect(connection_string)
            self.cursor = self.connection.cursor()
            return True
        except Exception as e:
            return str(e)
            
    def disconnect(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
    
    def execute_query(self, query, params=None):
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            return self.cursor
        except Exception as e:
            return str(e)
    
    def commit_changes(self):
        try:
            self.connection.commit()
            return True
        except Exception as e:
            return str(e)

# Database Connector for Editor de BD (SQL Server Authentication)
class EditorDatabaseConnector:
    def __init__(self, server, instance, database, username, password, driver):
        self.server = server
        self.instance = instance
        self.database = database
        self.username = username
        self.password = password
        self.driver = driver
        self.connection = None
        self.cursor = None
    
    def connect(self):
        try:
            connection_string = (
                f"DRIVER={{{self.driver}}};"
                f"SERVER={self.server}\\{self.instance};"
                f"DATABASE={self.database};"
                f"UID={self.username};"
                f"PWD={self.password};"
            )
            self.connection = pyodbc.connect(connection_string)
            self.cursor = self.connection.cursor()
            return True
        except Exception as e:
            return str(e)
            
    def disconnect(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
    
    def execute_query(self, query, params=None):
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            return self.cursor
        except Exception as e:
            return str(e)
    
    def commit_changes(self):
        try:
            self.connection.commit()
            return True
        except Exception as e:
            return str(e)
    
    def get_tables(self):
        try:
            self.cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
            tables = [row[0] for row in self.cursor.fetchall()]
            return sorted(tables)
        except Exception as e:
            return str(e)
    
    def get_columns(self, table):
        try:
            self.cursor.execute(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?", (table,))
            columns = [row[0] for row in self.cursor.fetchall()]
            return columns
        except Exception as e:
            return str(e)

# Initialize session for Editor de BD
def initialize_editor_session():
    defaults = {
        'editor_db_credentials': EDITOR_DB_CONFIG,
        'current_table': None,
        'column_names': [],
        'column_indices': {},
        'rules': [],
        'primary_key': None,
        'current_page': 0,
        'page_size': 100,
        'filter_query': None,
        'filter_info': "No hay filtro activo",
        'command_history': [],
        'preview_results': [],
        'notification': None,
        'selected_ids': [],
        'last_command': ''
    }
    for key, value in defaults.items():
        if key not in session or session[key] is None:
            session[key] = value
    session.modified = True

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, inicia sesión primero.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Admin required decorator
def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Acceso denegado. Se requiere permiso de administrador.', 'error')
            return redirect(url_for('portal'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Get user permissions
def get_user_permissions(user_id):
    db = PortalDatabaseConnector(**PORTAL_DB_CONFIG)
    if db.connect() is not True:
        return []
    cursor = db.execute_query(
        """
        SELECT a.route
        FROM Permissions p
        JOIN Apps a ON p.app_id = a.id
        WHERE p.user_id = ?
        """,
        (user_id,)
    )
    if isinstance(cursor, str):
        db.disconnect()
        return []
    permissions = [row[0] for row in cursor.fetchall()]
    db.disconnect()
    return permissions

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = PortalDatabaseConnector(**PORTAL_DB_CONFIG)
        result = db.connect()
        if result is not True:
            flash(f'Error de conexión a la base de datos: {result}', 'error')
            return render_template('login.html')
        
        cursor = db.execute_query(
            "SELECT id, password, is_admin FROM Users WHERE username = ?",
            (username,)
        )
        if isinstance(cursor, str):
            db.disconnect()
            flash(f'Error al consultar usuario: {cursor}', 'error')
            return render_template('login.html')
        
        user = cursor.fetchone()
        db.disconnect()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = username
            session['is_admin'] = user[2]
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('portal'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada.', 'success')
    return redirect(url_for('login'))

# Portal route
@app.route('/')
@login_required
def portal():
    user_permissions = get_user_permissions(session['user_id'])
    db = PortalDatabaseConnector(**PORTAL_DB_CONFIG)
    result = db.connect()
    if result is not True:
        flash(f'Error al conectar a la base de datos: {result}', 'error')
        return render_template('portal.html', apps=[])
    
    cursor = db.execute_query("SELECT id, name, route FROM Apps")
    if isinstance(cursor, str):
        db.disconnect()
        flash(f'Error al cargar aplicaciones: {cursor}', 'error')
        return render_template('portal.html', apps=[])
    
    apps = [{'id': row[0], 'name': row[1], 'route': row[2]} for row in cursor.fetchall()]
    db.disconnect()
    
    accessible_apps = [app for app in apps if app['route'] in user_permissions or session.get('is_admin')]
    return render_template('portal.html', apps=accessible_apps)

# Admin users route
@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    db = PortalDatabaseConnector(**PORTAL_DB_CONFIG)
    result = db.connect()
    if result is not True:
        flash(f'Error de conexión a la base de datos: {result}', 'error')
        return render_template('admin_users.html', users=[], apps=[])
    
    # Handle user creation
    if request.method == 'POST' and 'create_user' in request.form:
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        result = db.execute_query(
            "INSERT INTO Users (username, password, is_admin) VALUES (?, ?, ?)",
            (username, hashed_password, is_admin)
        )
        if isinstance(result, str):
            db.disconnect()
            flash(f'Error al crear usuario: {result}', 'error')
        else:
            db.commit_changes()
            flash(f'Usuario {username} creado exitosamente.', 'success')
    
    # Handle permission updates
    if request.method == 'POST' and 'update_permissions' in request.form:
        user_id = request.form.get('user_id')
        selected_apps = request.form.getlist('apps')
        
        result = db.execute_query("DELETE FROM Permissions WHERE user_id = ?", (user_id,))
        if isinstance(result, str):
            db.disconnect()
            flash(f'Error al limpiar permisos: {result}', 'error')
        else:
            db.commit_changes()
        
        for app_id in selected_apps:
            result = db.execute_query(
                "INSERT INTO Permissions (user_id, app_id) VALUES (?, ?)",
                (user_id, app_id)
            )
            if isinstance(result, str):
                db.disconnect()
                flash(f'Error al asignar permiso: {result}', 'error')
                break
        else:
            db.commit_changes()
            flash('Permisos actualizados exitosamente.', 'success')
    
    # Get users and apps
    cursor = db.execute_query("SELECT id, username, is_admin FROM Users")
    if isinstance(cursor, str):
        db.disconnect()
        flash(f'Error al cargar usuarios: {cursor}', 'error')
        return render_template('admin_users.html', users=[], apps=[])
    users = [{'id': row[0], 'username': row[1], 'is_admin': row[2]} for row in cursor.fetchall()]
    
    cursor = db.execute_query("SELECT id, name FROM Apps")
    if isinstance(cursor, str):
        db.disconnect()
        flash(f'Error al cargar aplicaciones: {cursor}', 'error')
        return render_template('admin_users.html', users=users, apps=[])
    apps = [{'id': row[0], 'name': row[1]} for row in cursor.fetchall()]
    
    for user in users:
        cursor = db.execute_query(
            "SELECT app_id FROM Permissions WHERE user_id = ?",
            (user['id'],)
        )
        if isinstance(cursor, str):
            user['permissions'] = []
        else:
            user['permissions'] = [row[0] for row in cursor.fetchall()]
    
    db.disconnect()
    return render_template('admin_users.html', users=users, apps=apps)

# Editor de BD route
@app.route('/editor-bd', methods=['GET', 'POST'])
@login_required
def editor_bd():
    if '/editor-bd' not in get_user_permissions(session['user_id']) and not session.get('is_admin'):
        flash('Acceso denegado a Editor de BD.', 'error')
        return redirect(url_for('portal'))
    
    initialize_editor_session()
    
    db_config = session['editor_db_credentials'] or EDITOR_DB_CONFIG
    db = EditorDatabaseConnector(**db_config)
    tables = []
    
    result = db.connect()
    if result is True:
        tables = db.get_tables()
        if isinstance(tables, str):
            session['notification'] = {'type': 'error', 'message': f"No se pudieron cargar las tablas: {tables}"}
            tables = []
        db.disconnect()
    
    if request.method == 'POST':
        action = request.form.get('action')
        # Update selected_ids for actions that modify the table view
        if action in ['preview_changes', 'apply_changes', 'filter', 'clear_filter', 'prev_page', 'next_page', 'update_page_size', 'add_rule', 'clear_rules']:
            session['selected_ids'] = request.form.getlist('selected_ids')
        
        # Connect to database
        if action == 'connect':
            db_config = {
                'server': request.form.get('server', EDITOR_DB_CONFIG['server']),
                'instance': request.form.get('instance', EDITOR_DB_CONFIG['instance']),
                'database': request.form.get('database', EDITOR_DB_CONFIG['database']),
                'username': request.form.get('username', EDITOR_DB_CONFIG['username']),
                'password': request.form.get('password', EDITOR_DB_CONFIG['password']),
                'driver': EDITOR_DB_CONFIG['driver']
            }
            db = EditorDatabaseConnector(**db_config)
            result = db.connect()
            if result is True:
                session['editor_db_credentials'] = db_config
                tables = db.get_tables()
                db.disconnect()
                if isinstance(tables, str):
                    session['notification'] = {'type': 'error', 'message': f"No se pudieron cargar las tablas: {tables}"}
                    return render_paginated_data(db, tables=tables)
                session['notification'] = {'type': 'success', 'message': f"Conectado a {db_config['server']}\\{db_config['instance']} - {db_config['database']}"}
                session.modified = True
                return render_paginated_data(db, tables=tables)
            session['notification'] = {'type': 'error', 'message': f"No se pudo conectar: {result}"}
            return render_paginated_data(db, tables=tables)
        
        # Load data
        elif action == 'load_data':
            result = db.connect()
            if result is not True:
                session['notification'] = {'type': 'error', 'message': f"No hay conexión activa: {result}"}
                return render_paginated_data(db, tables=tables)
            table = request.form.get('table')
            if not table:
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': "Seleccione una tabla."}
                return render_paginated_data(db, tables=tables)
            
            cursor = db.execute_query(f"SELECT TOP 1 * FROM {table}")
            if isinstance(cursor, str):
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': f"Error al cargar datos: {cursor}"}
                return render_paginated_data(db, tables=tables)
            
            session['current_table'] = table
            session['column_names'] = [desc[0] for desc in cursor.description]
            session['column_indices'] = {name: idx for idx, name in enumerate(session['column_names'])}
            session['current_page'] = 0
            session['filter_query'] = None
            session['filter_info'] = "No hay filtro activo"
            session['preview_results'] = []
            session['selected_ids'] = []
            session['last_command'] = ''
            session['primary_key'] = detect_primary_key(db, table)
            if not session['primary_key']:
                session['primary_key'] = session['column_names'][0] if session['column_names'] else '1'
            
            session.modified = True
            db.disconnect()
            return render_paginated_data(db, tables=tables)
        
        # Clear filter
        elif action == 'clear_filter':
            session['filter_query'] = None
            session['filter_info'] = "No hay filtro activo"
            session['current_page'] = 0
            session['last_command'] = ''
            session['notification'] = {'type': 'success', 'message': "Filtro eliminado."}
            session.modified = True
            return render_paginated_data(db, tables=tables)
        
        # Clear rules
        elif action == 'clear_rules':
            session['rules'] = []
            session['preview_results'] = []
            session['notification'] = {'type': 'success', 'message': "Reglas eliminadas."}
            session.modified = True
            return render_paginated_data(db, tables=tables)
        
        # Filter data
        elif action == 'filter':
            result = db.connect()
            if result is not True or not session.get('current_table'):
                session['notification'] = {'type': 'error', 'message': f"No hay tabla seleccionada o conexión activa: {result}"}
                return render_paginated_data(db, tables=tables)
            
            command = request.form.get('command')
            session['last_command'] = command
            if not command:
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': "Comando vacío."}
                return render_paginated_data(db, tables=tables)
            
            if command not in session['command_history']:
                session['command_history'].insert(0, command)
                if len(session['command_history']) > 50:
                    session['command_history'].pop()
            
            table = session['current_table']
            if command.lower() == "mostrar todos los registros":
                session['filter_query'] = None
                session['filter_info'] = "No hay filtro activo"
                session['current_page'] = 0
            else:
                column_filter_pattern = r"filtrar\s+columna\s+(\w+)\s+donde\s+(.+)"
                complex_filter_pattern = r"mostrar\s+registros\s+donde\s+(.+)"
                if re.match(column_filter_pattern, command, re.IGNORECASE):
                    match = re.match(column_filter_pattern, command, re.IGNORECASE)
                    column_name, condition = match.group(1), match.group(2).lower().strip()
                    if column_name not in session['column_indices']:
                        db.disconnect()
                        session['notification'] = {'type': 'error', 'message': f"La columna '{column_name}' no existe."}
                        return render_paginated_data(db, tables=tables)
                    
                    if condition == "está vacío":
                        session['filter_query'] = f"SELECT * FROM {table} WHERE {column_name} IS NULL OR {column_name} = ''"
                        session['filter_info'] = f"Columna '{column_name}' donde está vacío"
                    elif condition == "no está vacío":
                        session['filter_query'] = f"SELECT * FROM {table} WHERE {column_name} IS NOT NULL AND {column_name} != ''"
                        session['filter_info'] = f"Columna '{column_name}' donde no está vacío"
                    elif "contiene" in condition:
                        value = condition.split("contiene")[1].strip()
                        session['filter_query'] = f"SELECT * FROM {table} WHERE {column_name} LIKE '%{value}%'"
                        session['filter_info'] = f"Columna '{column_name}' donde contiene '{value}'"
                    elif "es igual a" in condition:
                        value = condition.split("es igual a")[1].strip()
                        session['filter_query'] = f"SELECT * FROM {table} WHERE {column_name} = '{value}'"
                        session['filter_info'] = f"Columna '{column_name}' donde es igual a '{value}'"
                    else:
                        db.disconnect()
                        session['notification'] = {'type': 'error', 'message': "Condición no soportada."}
                        return render_paginated_data(db, tables=tables)
                    
                    session['current_page'] = 0
                elif re.match(complex_filter_pattern, command, re.IGNORECASE):
                    match = re.match(complex_filter_pattern, command, re.IGNORECASE)
                    conditions = match.group(1).split(" y ")
                    filter_conditions = []
                    filter_description = []
                    for cond in conditions:
                        cond = cond.strip().lower()
                        sub_match = re.match(r"(\w+)\s+(.+)", cond)
                        if not sub_match:
                            db.disconnect()
                            session['notification'] = {'type': 'error', 'message': f"Condición inválida: {cond}"}
                            return render_paginated_data(db, tables=tables)
                        column_name, sub_condition = sub_match.group(1), sub_match.group(2).strip()
                        if column_name not in session['column_indices']:
                            db.disconnect()
                            session['notification'] = {'type': 'error', 'message': f"La columna '{column_name}' no existe."}
                            return render_paginated_data(db, tables=tables)
                        
                        if sub_condition == "está vacío":
                            filter_conditions.append(f"{column_name} IS NULL OR {column_name} = ''")
                            filter_description.append(f"{column_name} está vacío")
                        elif "contiene" in sub_condition:
                            value = sub_condition.split("contiene")[1].strip()
                            filter_conditions.append(f"{column_name} LIKE '%{value}%'")
                            filter_description.append(f"{column_name} contiene '{value}'")
                        else:
                            db.disconnect()
                            session['notification'] = {'type': 'error', 'message': f"Condición no soportada: {sub_condition}"}
                            return render_paginated_data(db, tables=tables)
                    
                    session['filter_query'] = f"SELECT * FROM {table} WHERE {' AND '.join(filter_conditions)}"
                    session['filter_info'] = " y ".join(filter_description)
                    session['current_page'] = 0
                else:
                    db.disconnect()
                    session['notification'] = {'type': 'error', 'message': "Comando no reconocido."}
                    return render_paginated_data(db, tables=tables)
            
            session.modified = True
            db.disconnect()
            return render_paginated_data(db, tables=tables)
        
        # Change page
        elif action == 'prev_page':
            if session['current_page'] > 0:
                session['current_page'] -= 1
            session['notification'] = {'type': 'success', 'message': f"Página cambiada a {session['current_page'] + 1}."}
            session.modified = True
            return render_paginated_data(db, tables=tables)
        
        elif action == 'next_page':
            result = db.connect()
            if result is not True or not session.get('current_table'):
                session['notification'] = {'type': 'error', 'message': f"No hay conexión o tabla seleccionada: {result}"}
                return render_paginated_data(db, tables=tables)
            _, total_pages = get_paginated_data(db, session['current_table'], session['current_page'], session['page_size'], session['filter_query'])
            if session['current_page'] < total_pages - 1:
                session['current_page'] += 1
            session['notification'] = {'type': 'success', 'message': f"Página cambiada a {session['current_page'] + 1}."}
            session.modified = True
            db.disconnect()
            return render_paginated_data(db, tables=tables)
        
        # Update page size
        elif action == 'update_page_size':
            try:
                new_page_size = int(request.form.get('page_size', 100))
                if new_page_size < 10 or new_page_size > 1000:
                    session['notification'] = {'type': 'error', 'message': "El tamaño de página debe estar entre 10 y 1000."}
                else:
                    session['page_size'] = new_page_size
                    session['current_page'] = 0
                    session['notification'] = {'type': 'success', 'message': f"Tamaño de página actualizado a {new_page_size}."}
            except ValueError:
                session['notification'] = {'type': 'error', 'message': "El tamaño de página debe ser un número válido."}
            session.modified = True
            return render_paginated_data(db, tables=tables)
        
        # Add rule
        elif action == 'add_rule':
            column = request.form.get('column')
            pattern = request.form.get('pattern')
            replacement = request.form.get('replacement')
            if column and pattern and replacement:
                session['rules'].append({"column": column, "pattern": pattern, "replacement": replacement})
                session['notification'] = {'type': 'success', 'message': "Regla añadida correctamente."}
            else:
                session['notification'] = {'type': 'error', 'message': "Faltan datos en la regla."}
            session.modified = True
            return render_paginated_data(db, tables=tables)
        
        # Preview changes
        elif action == 'preview_changes':
            result = db.connect()
            if result is not True or not session.get('current_table'):
                session['notification'] = {'type': 'error', 'message': f"No hay conexión o tabla seleccionada: {result}"}
                return render_paginated_data(db, tables=tables)
            
            selected_ids = request.form.getlist('selected_ids')
            if not selected_ids:
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': "Seleccione al menos un registro."}
                return render_paginated_data(db, tables=tables)
            
            if not session['rules']:
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': "No hay reglas definidas."}
                return render_paginated_data(db, tables=tables)
            
            clients, _ = get_paginated_data(db, session['current_table'], session['current_page'], session['page_size'], session['filter_query'])
            session['preview_results'] = ["Vista previa de cambios:"]
            
            for client_id in selected_ids:
                client = next((c for c in clients if str(c[session['column_indices'][session['primary_key']]]) == client_id), None)
                if client is None:
                    continue
                session['preview_results'].append(f"Registro {client_id}:")
                for rule in session['rules']:
                    col_idx = session['column_indices'].get(rule['column'])
                    if col_idx is None:
                        session['preview_results'].append(f" Columna {rule['column']} no encontrada.")
                        continue
                    original = str(client[col_idx]) if client[col_idx] is not None else ""
                    try:
                        modified = re.sub(rule['pattern'], rule['replacement'], original, flags=re.IGNORECASE)
                        if modified != original:
                            session['preview_results'].append(f" Columna {rule['column']}:")
                            session['preview_results'].append(f" Original: {original}")
                            session['preview_results'].append(f" Modificado: {modified}")
                    except re.error:
                        session['preview_results'].append(f" Error en la regla para {rule['column']}: Patrón inválido")
                session['preview_results'].append("")
            
            session['notification'] = {'type': 'success', 'message': "Vista previa generada. Revise el panel lateral."}
            session.modified = True
            db.disconnect()
            return render_paginated_data(db, tables=tables)
        
        # Apply changes
        elif action == 'apply_changes':
            result = db.connect()
            if result is not True or not session.get('current_table'):
                session['notification'] = {'type': 'error', 'message': f"No hay conexión o tabla seleccionada: {result}"}
                return render_paginated_data(db, tables=tables)
            
            selected_ids = request.form.getlist('selected_ids')
            if not selected_ids:
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': "Seleccione al menos un registro."}
                return render_paginated_data(db, tables=tables)
            
            if not session['rules']:
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': "No hay reglas definidas."}
                return render_paginated_data(db, tables=tables)
            
            updated_records = 0
            results = ["Resultado de la aplicación de cambios:"]
            
            for client_id in selected_ids:
                updates = {}
                for rule in session['rules']:
                    col_idx = session['column_indices'].get(rule['column'])
                    if col_idx is None:
                        results.append(f"Columna {rule['column']} no encontrada.")
                        continue
                    query = f"SELECT {rule['column']} FROM {session['current_table']} WHERE {session['primary_key']} = ?"
                    cursor = db.execute_query(query, [client_id])
                    if isinstance(cursor, str):
                        results.append(f"Error al obtener datos para ID {client_id}: {cursor}")
                        continue
                    row = cursor.fetchone()
                    if not row:
                        results.append(f"No se encontró registro con ID {client_id}.")
                        continue
                    original = str(row[0]) if row[0] is not None else ""
                    try:
                        modified = re.sub(rule['pattern'], rule['replacement'], original, flags=re.IGNORECASE)
                        if modified != original:
                            updates[rule['column']] = modified
                    except re.error as e:
                        results.append(f"Error en la regla para {rule['column']}: {str(e)}")
                
                if updates:
                    update_parts = [f"{col} = ?" for col in updates.keys()]
                    update_query = f"UPDATE {session['current_table']} SET {', '.join(update_parts)} WHERE {session['primary_key']} = ?"
                    params = list(updates.values()) + [client_id]
                    result = db.execute_query(update_query, params)
                    if isinstance(result, str):
                        results.append(f"Error al actualizar ID {client_id}: {result}")
                        continue
                    commit_result = db.commit_changes()
                    if commit_result is True:
                        updated_records += 1
                    else:
                        results.append(f"Error al confirmar cambios para ID {client_id}: {commit_result}")
            
            session['preview_results'] = results + [f"Cambios aplicados: {updated_records} registros actualizados."]
            session['notification'] = {'type': 'success', 'message': f"Cambios aplicados: {updated_records} registros actualizados."}
            session.modified = True
            db.disconnect()
            return render_paginated_data(db, tables=tables)
        
        # Export CSV
        elif action == 'export_csv':
            result = db.connect()
            if result is not True or not session.get('current_table'):
                session['notification'] = {'type': 'error', 'message': f"No hay conexión o tabla seleccionada: {result}"}
                return render_paginated_data(db, tables=tables)
            
            table = session['current_table']
            query = session['filter_query'] if session['filter_query'] else f"SELECT * FROM {table}"
            cursor = db.execute_query(query)
            if isinstance(cursor, str):
                db.disconnect()
                session['notification'] = {'type': 'error', 'message': f"Error al exportar datos: {cursor}"}
                return render_paginated_data(db, tables=tables)
            
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow([desc[0] for desc in cursor.description])
            for row in cursor.fetchall():
                writer.writerow([str(val) if val is not None else '' for val in row])
            
            db.disconnect()
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment;filename={table}_export.csv"}
            )
    
    return render_paginated_data(db, tables=tables)

# Helper functions for Editor de BD
def detect_primary_key(db, table):
    try:
        query = """
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
        WHERE TABLE_NAME = ? AND CONSTRAINT_NAME LIKE 'PK%'
        """
        cursor = db.execute_query(query, (table,))
        if isinstance(cursor, str):
            return None
        result = cursor.fetchone()
        return result[0] if result else None
    except Exception as e:
        return None

def get_paginated_data(db, table, page, page_size, filter_query=None):
    offset = page * page_size
    order_by = session['primary_key'] if session['primary_key'] else '1'
    if filter_query:
        query = f"{filter_query} ORDER BY {order_by} OFFSET {offset} ROWS FETCH NEXT {page_size} ROWS ONLY"
    else:
        query = f"SELECT * FROM {table} ORDER BY {order_by} OFFSET {offset} ROWS FETCH NEXT {page_size} ROWS ONLY"
    
    cursor = db.execute_query(query)
    if isinstance(cursor, str):
        return [], 1
    data = [list(row) for row in cursor.fetchall()]
    
    count_query = f"SELECT COUNT(*) FROM {table}" if not filter_query else f"SELECT COUNT(*) FROM ({filter_query}) AS filtered"
    cursor = db.execute_query(count_query)
    total_records = cursor.fetchone()[0] if not isinstance(cursor, str) else 0
    total_pages = (total_records + page_size - 1) // page_size
    return data, total_pages

def render_paginated_data(db, tables=None):
    initialize_editor_session()  # Ensure session is initialized
    tables = tables or []
    clients = []
    total_pages = 1
    
    if session.get('current_table'):
        result = db.connect()
        if result is True:
            clients, total_pages = get_paginated_data(db, session['current_table'], session['current_page'], session['page_size'], session['filter_query'])
            tables = db.get_tables() if not tables else tables
            db.disconnect()
        else:
            session['notification'] = {'type': 'error', 'message': f"No se pudo conectar para recargar datos: {result}"}
    
    notification = session.get('notification')
    session['notification'] = None
    session.modified = True
    
    return render_template('index.html', 
                          tables=tables,
                          clients=clients,
                          column_names=session['column_names'],
                          filter_info=session['filter_info'],
                          rules=session['rules'],
                          command_history=session['command_history'],
                          current_page=session['current_page'] + 1,
                          total_pages=total_pages,
                          page_size=session['page_size'],
                          column_indices=session['column_indices'],
                          primary_key=session['primary_key'],
                          preview_results=session['preview_results'],
                          notification=notification,
                          selected_ids=session['selected_ids'],
                          session=session)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)