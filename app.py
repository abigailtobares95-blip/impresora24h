import os
import sqlite3
import random
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import pypdf
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'clave_secreta_impresora24h'

UPLOAD_FOLDER = 'documentos'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Inicialización de la base de datos
def init_db():
    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    
    # Tabla de Usuarios comunes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Tabla de Pedidos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pedidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL,
            documento TEXT NOT NULL,
            paginas TEXT NOT NULL,
            cantidad INTEGER NOT NULL,
            tipo_impresion TEXT NOT NULL,
            precio_pagina INTEGER NOT NULL,
            total INTEGER NOT NULL,
            metodo_pago TEXT NOT NULL,
            fecha TEXT NOT NULL
        )
    ''')

    # Tabla de Configuración (Precios y Credenciales de Admin)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config (
            clave TEXT PRIMARY KEY,
            valor TEXT NOT NULL
        )
    ''')

    # Tabla de Dispositivos de Confianza (para recordar equipos autorizados 2FA)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dispositivos_confianza (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_dispositivo TEXT UNIQUE NOT NULL,
            ip TEXT NOT NULL,
            navegador TEXT NOT NULL,
            fecha TEXT NOT NULL
        )
    ''')
    
    # Valores por defecto iniciales
    cursor.execute("INSERT OR IGNORE INTO config (clave, valor) VALUES ('precio_bn', '100')")
    cursor.execute("INSERT OR IGNORE INTO config (clave, valor) VALUES ('precio_color', '200')")
    cursor.execute("INSERT OR IGNORE INTO config (clave, valor) VALUES ('admin_user', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO config (clave, valor) VALUES ('admin_password', 'admin123')")

    conn.commit()
    conn.close()

init_db()

# Funciones auxiliares
def obtener_precios():
    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute("SELECT clave, valor FROM config WHERE clave IN ('precio_bn', 'precio_color')")
    config = {fila[0]: int(fila[1]) for fila in cursor.fetchall()}
    conn.close()
    return config.get('precio_bn', 100), config.get('precio_color', 200)

def obtener_credenciales_admin():
    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute("SELECT clave, valor FROM config WHERE clave IN ('admin_user', 'admin_password')")
    res = {fila[0]: fila[1] for fila in cursor.fetchall()}
    conn.close()
    return res.get('admin_user', 'admin'), res.get('admin_password', 'admin123')


# Rutas de Autenticación de Usuarios Comunes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nombre = request.form.get('nombre').strip()
        password = request.form.get('password').strip()

        conn = sqlite3.connect('impresora.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE nombre = ? AND password = ?', (nombre, password))
        usuario = cursor.fetchone()
        conn.close()

        if usuario:
            session['usuario'] = nombre
            flash(f'¡Bienvenido/a, {nombre}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form.get('nombre').strip()
        password = request.form.get('password').strip()

        if not nombre or not password:
            flash('Por favor completa todos los campos.', 'warning')
            return redirect(url_for('registro'))

        conn = sqlite3.connect('impresora.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO usuarios (nombre, password) VALUES (?, ?)', (nombre, password))
            conn.commit()
            conn.close()
            flash('Cuenta creada con éxito. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('El nombre de usuario ya existe. Elige otro.', 'danger')

    return render_template('registro.html')


@app.route('/logout')
def logout():
    session.pop('usuario', None)
    flash('Has cerrado sesión correctamente.', 'success')
    return redirect(url_for('login'))


# Panel de Administración con 2FA y Dispositivos de Confianza

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    ip_cliente = request.remote_addr
    token_cookie = request.cookies.get('admin_device_token')

    # Verificar si el navegador ya es un dispositivo de confianza guardado
    if token_cookie:
        conn = sqlite3.connect('impresora.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM dispositivos_confianza WHERE token_dispositivo = ?', (token_cookie,))
        dispositivo = cursor.fetchone()
        conn.close()
        if dispositivo:
            session['admin'] = True
            return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        user_ingresado = request.form.get('admin_user').strip()
        pass_ingresada = request.form.get('admin_password').strip()
        
        db_user, db_pass = obtener_credenciales_admin()

        if user_ingresado == db_user and pass_ingresada == db_pass:
            codigo_2fa = str(random.randint(1000, 9999))
            session['temp_2fa'] = codigo_2fa
            
            # 🚨 ALERTA DE SEGURIDAD EN LA TERMINAL
            print("\n" + "🚨"*28)
            print(f"⚠️ ¡ALERTA DE SEGURIDAD! Solicitud de acceso al panel Admin.")
            print(f"🌐 Dirección IP: {ip_cliente}")
            print(f"🔑 CÓDIGO DE VERIFICACIÓN 2FA: [ {codigo_2fa} ]")
            print("🚨"*28 + "\n")
            
            return redirect(url_for('admin_verificar_2fa'))
        else:
            print(f"\n❌ [ALERTA] Intento fallido con credenciales incorrectas desde IP: {ip_cliente}\n")
            flash('Usuario o contraseña incorrectos.', 'danger')
            
    return render_template('admin_login.html')

@app.route('/admin/verificar', methods=['GET', 'POST'])
def admin_verificar_2fa():
    if 'temp_2fa' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        codigo_ingresado = request.form.get('codigo_2fa').strip()
        confiar_dispositivo = request.form.get('confiar') == 'on'

        if codigo_ingresado == session['temp_2fa']:
            session.pop('temp_2fa', None)
            session['admin'] = True

            resp = make_response(redirect(url_for('admin_panel')))
            
            if confiar_dispositivo:
                token_unico = f"token_dev_{random.randint(100000, 999999)}_{datetime.now().timestamp()}"
                ip_cliente = request.remote_addr
                user_agent = request.user_agent.string[:50]
                fecha_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                conn = sqlite3.connect('impresora.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO dispositivos_confianza (token_dispositivo, ip, navegador, fecha) VALUES (?, ?, ?, ?)',
                               (token_unico, ip_cliente, user_agent, fecha_str))
                conn.commit()
                conn.close()

                resp.set_cookie('admin_device_token', token_unico, max_age=60*60*24*365)
                flash('Dispositivo guardado como de confianza.', 'success')
            else:
                flash('¡Acceso concedido por 2FA!', 'success')

            return resp
        else:
            flash('Código de verificación incorrecto.', 'danger')

    return render_template('admin_2fa.html')

@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    precio_bn, precio_color = obtener_precios()
    db_user, _ = obtener_credenciales_admin()

    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, nombre, password FROM usuarios')
    usuarios = cursor.fetchall()

    cursor.execute('SELECT * FROM pedidos ORDER BY id DESC')
    pedidos = cursor.fetchall()

    cursor.execute('SELECT id, ip, navegador, fecha FROM dispositivos_confianza')
    dispositivos = cursor.fetchall()
    
    conn.close()

    return render_template('admin_panel.html', usuarios=usuarios, pedidos=pedidos, dispositivos=dispositivos, precio_bn=precio_bn, precio_color=precio_color, admin_user=db_user)

@app.route('/admin/actualizar_precios', methods=['POST'])
def actualizar_precios():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    nuevo_bn = request.form.get('precio_bn')
    nuevo_color = request.form.get('precio_color')

    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE config SET valor = ? WHERE clave = 'precio_bn'", (nuevo_bn,))
    cursor.execute("UPDATE config SET valor = ? WHERE clave = 'precio_color'", (nuevo_color,))
    conn.commit()
    conn.close()
    flash('Precios actualizados.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/actualizar_credenciales', methods=['POST'])
def actualizar_credenciales():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    nuevo_usuario = request.form.get('nuevo_user').strip()
    nueva_password = request.form.get('nueva_pass').strip()

    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE config SET valor = ? WHERE clave = 'admin_user'", (nuevo_usuario,))
    cursor.execute("UPDATE config SET valor = ? WHERE clave = 'admin_password'", (nueva_password,))
    conn.commit()
    conn.close()
    flash('Credenciales de admin actualizadas.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/eliminar_usuario/<int:user_id>', methods=['POST'])
def eliminar_usuario(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM usuarios WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('Usuario eliminado.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/revocar_dispositivo/<int:dev_id>', methods=['POST'])
def revocar_dispositivo(dev_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM dispositivos_confianza WHERE id = ?', (dev_id,))
    conn.commit()
    conn.close()
    flash('Acceso revocado a ese dispositivo.', 'warning')
    return redirect(url_for('admin_panel'))

@app.route('/admin/logout')
def admin_logout():
    resp = make_response(redirect(url_for('admin_login')))
    session.pop('admin', None)
    session.pop('temp_2fa', None)
    resp.set_cookie('admin_device_token', '', expires=0)
    flash('Sesión de administrador cerrada.', 'success')
    return resp


# Rutas del Sistema de Impresión (Usuarios comunes)

@app.route('/')
def index():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', usuario=session['usuario'])


@app.route('/cargar_pdf', methods=['POST'])
def cargar_pdf():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    if 'archivo_pdf' not in request.files:
        flash('No se seleccionó archivo.', 'danger')
        return redirect(url_for('index'))
    file = request.files['archivo_pdf']
    if file and file.filename.endswith('.pdf'):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        reader = pypdf.PdfReader(filepath)
        total_paginas = len(reader.pages)
        return render_template('paginas.html', filename=file.filename, total_paginas=total_paginas)
    flash('Sube un archivo PDF válido.', 'danger')
    return redirect(url_for('index'))


@app.route('/procesar_paginas', methods=['POST'])
def procesar_paginas():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    filename = request.form.get('filename')
    total_paginas = int(request.form.get('total_paginas'))
    modo_seleccion = request.form.get('modo_seleccion')
    tipo_impresion = request.form.get('tipo_impresion')

    paginas_seleccionadas = []
    if modo_seleccion == 'todas':
        paginas_seleccionadas = list(range(1, total_paginas + 1))
    elif modo_seleccion == 'personalizado':
        paginas_input = request.form.get('paginas_input', '').strip()
        if paginas_input:
            for parte in paginas_input.split(','):
                parte = parte.strip()
                if '-' in parte:
                    try:
                        inicio, fin = map(int, parte.split('-'))
                        if 1 <= inicio <= fin <= total_paginas:
                            paginas_seleccionadas.extend(range(inicio, fin + 1))
                    except ValueError:
                        pass
                elif parte.isdigit():
                    p = int(parte)
                    if 1 <= p <= total_paginas:
                        paginas_seleccionadas.append(p)

    paginas_seleccionadas = sorted(list(set(paginas_seleccionadas)))
    if not paginas_seleccionadas:
        flash('Selecciona al menos una página.', 'warning')
        return render_template('paginas.html', filename=filename, total_paginas=total_paginas)

    precio_bn, precio_color = obtener_precios()
    precio_pagina = precio_bn if tipo_impresion == 'bn' else precio_color
    cantidad_paginas = len(paginas_seleccionadas)
    total_pagar = cantidad_paginas * precio_pagina

    texto_qr = f"PAGO IMPRESORA 24H\nUsuario: {session['usuario']}\nDoc: {filename}\nTotal: ${total_pagar}"
    qr_img = qrcode.make(texto_qr)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    paginas_texto = ", ".join(map(str, paginas_seleccionadas))

    return render_template('resumen.html', filename=filename, paginas_texto=paginas_texto, cantidad_paginas=cantidad_paginas, tipo_impresion='Blanco y Negro' if tipo_impresion == 'bn' else 'Color', precio_pagina=precio_pagina, total_pagar=total_pagar, qr_b64=qr_b64)


@app.route('/confirmar_pago', methods=['POST'])
def confirmar_pago():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    filename = request.form.get('filename')
    paginas_texto = request.form.get('paginas_texto')
    cantidad = int(request.form.get('cantidad'))
    tipo_impresion = request.form.get('tipo_impresion')
    precio_pagina = int(request.form.get('precio_pagina'))
    total = int(request.form.get('total'))
    metodo_pago = request.form.get('metodo_pago')
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    usuario = session['usuario']

    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO pedidos (usuario, documento, paginas, cantidad, tipo_impresion, precio_pagina, total, metodo_pago, fecha) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                   (usuario, filename, paginas_texto, cantidad, tipo_impresion, precio_pagina, total, metodo_pago, fecha))
    pedido_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return render_template('ticket.html', pedido_id=pedido_id, usuario=usuario, filename=filename, paginas_texto=paginas_texto, cantidad=cantidad, tipo_impresion=tipo_impresion, precio_pagina=precio_pagina, total=total, metodo_pago=metodo_pago, fecha=fecha)


@app.route('/pedidos')
def ver_pedidos():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('impresora.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM pedidos ORDER BY id DESC')
    pedidos = cursor.fetchall()
    conn.close()
    return render_template('pedidos.html', pedidos=pedidos, usuario_actual=session['usuario'])


if __name__ == '__main__':
    app.run(debug=True)