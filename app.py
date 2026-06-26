from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, hashlib, os, random

app = Flask(__name__)
app.secret_key = 'clave_super_secreta_2026'

DB = 'academico.db'

# ── Utilidades ──────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def solo_admin_docente():
    return session.get('rol') in ['admin', 'docente']

def solo_lectura():
    """Devuelve True si el usuario actual es de rol 'usuario' (solo lectura)."""
    return session.get('rol') == 'usuario'

def generar_captcha():
    """Genera una operación aritmética simple y devuelve (pregunta, respuesta)."""
    ops = ['+', '-', '×']
    op  = random.choice(ops)
    if op == '+':
        a, b = random.randint(1, 15), random.randint(1, 15)
        return f"{a} + {b}", a + b
    elif op == '-':
        a = random.randint(5, 20)
        b = random.randint(1, a)
        return f"{a} - {b}", a - b
    else:  # ×
        a, b = random.randint(2, 9), random.randint(2, 9)
        return f"{a} × {b}", a * b

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre   TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            rol      TEXT NOT NULL CHECK(rol IN ('admin','docente','usuario'))
        );
        CREATE TABLE IF NOT EXISTS sedes (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre           TEXT NOT NULL,
            tipo_institucion TEXT,
            ubicacion        TEXT
        );
        CREATE TABLE IF NOT EXISTS actividades (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre        TEXT NOT NULL,
            tipo          TEXT,
            descripcion   TEXT,
            fecha_entrega TEXT,
            asignatura    TEXT,
            estado        TEXT DEFAULT 'Pendiente'
        );
        CREATE TABLE IF NOT EXISTS asignaturas (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre         TEXT NOT NULL,
            docente        TEXT,
            area_academica TEXT
        );
        CREATE TABLE IF NOT EXISTS evidencias (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            actividad      TEXT,
            tipo_evidencia TEXT,
            descripcion    TEXT,
            archivo        TEXT,
            usuario_id     INTEGER
        );
        CREATE TABLE IF NOT EXISTS responsables (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre        TEXT NOT NULL,
            cargo         TEXT,
            asignatura_id INTEGER REFERENCES asignaturas(id)
        );
    ''')

    # Migración: agregar columna asignatura_id si no existe (BD existente)
    cols_resp = [row[1] for row in cur.execute("PRAGMA table_info(responsables)").fetchall()]
    if 'asignatura_id' not in cols_resp:
        cur.execute("ALTER TABLE responsables ADD COLUMN asignatura_id INTEGER REFERENCES asignaturas(id)")

    # Migración: agregar columna archivo a evidencias si no existe
    cols_evi = [row[1] for row in cur.execute("PRAGMA table_info(evidencias)").fetchall()]
    if 'archivo' not in cols_evi:
        cur.execute("ALTER TABLE evidencias ADD COLUMN archivo TEXT")

    # Migración: agregar columna estado a actividades si no existe
    cols_act = [row[1] for row in cur.execute("PRAGMA table_info(actividades)").fetchall()]
    if 'estado' not in cols_act:
        cur.execute("ALTER TABLE actividades ADD COLUMN estado TEXT DEFAULT 'Pendiente'")

    # Solo insertar datos si la tabla usuarios está vacía
    existing = cur.execute('SELECT COUNT(*) FROM usuarios').fetchone()[0]
    if existing == 0:
        cur.executemany(
            'INSERT INTO usuarios (nombre, username, password, rol) VALUES (?,?,?,?)',
            [
                ('Administrador', 'admin',   hash_pw('admin123'),   'admin'),
                ('Dr. Martínez',  'docente', hash_pw('docente123'), 'docente'),
                ('Ana López',     'usuario', hash_pw('usuario123'), 'usuario'),
            ]
        )
        cur.executemany(
            'INSERT INTO asignaturas (nombre, docente, area_academica) VALUES (?,?,?)',
            [
                ('Matemáticas',  'Dr. Martínez', 'Ciencias Exactas'),
                ('Historia',     'Lic. Torres',  'Humanidades'),
                ('Programación', 'Dr. Martínez', 'Tecnología'),
            ]
        )
        cur.executemany(
            'INSERT INTO actividades (nombre, tipo, descripcion, fecha_entrega, asignatura) VALUES (?,?,?,?,?)',
            [
                ('Examen Parcial', 'Evaluación', 'Primer examen del semestre', '2026-06-10', 'Matemáticas'),
                ('Proyecto Final', 'Proyecto',   'Desarrollo de app web',      '2026-07-01', 'Programación'),
                ('Ensayo',         'Tarea',      'Ensayo sobre la revolución', '2026-05-30', 'Historia'),
            ]
        )
        cur.executemany(
            'INSERT INTO sedes (nombre, tipo_institucion, ubicacion) VALUES (?,?,?)',
            [
                ('Sede Central', 'Pública', 'Ciudad de México'),
                ('Sede Norte',   'Privada', 'Monterrey'),
            ]
        )
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════
#  LOGIN / LOGOUT
# ══════════════════════════════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Generar captcha nuevo si no existe en sesión o al recargar GET
    if request.method == 'GET' or 'captcha_respuesta' not in session:
        pregunta, respuesta = generar_captcha()
        session['captcha_pregunta']  = pregunta
        session['captcha_respuesta'] = respuesta

    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        password  = request.form.get('password', '').strip()
        rol_sel   = request.form.get('rol', '').strip()
        captcha_input = request.form.get('captcha', '').strip()

        # Validar captcha
        try:
            captcha_ok = int(captcha_input) == session.get('captcha_respuesta')
        except (ValueError, TypeError):
            captcha_ok = False

        if not captcha_ok:
            # Regenerar captcha después de fallo
            pregunta, respuesta = generar_captcha()
            session['captcha_pregunta']  = pregunta
            session['captcha_respuesta'] = respuesta
            flash('Verificación incorrecta. Inténtalo de nuevo.', 'error')
            return render_template('index.html', captcha_pregunta=session['captcha_pregunta'])

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM usuarios WHERE username=? AND password=? AND rol=?',
            (username, hash_pw(password), rol_sel)
        ).fetchone()
        conn.close()

        if user:
            session.pop('captcha_pregunta',  None)
            session.pop('captcha_respuesta', None)
            session['user_id']  = user['id']
            session['nombre']   = user['nombre']
            session['username'] = user['username']
            session['rol']      = user['rol']
            return redirect(url_for('menu'))
        else:
            # Regenerar captcha en cada intento fallido
            pregunta, respuesta = generar_captcha()
            session['captcha_pregunta']  = pregunta
            session['captcha_respuesta'] = respuesta
            flash('Credenciales incorrectas o rol no coincide.', 'error')

    return render_template('index.html', captcha_pregunta=session['captcha_pregunta'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/captcha/refresh')
def captcha_refresh():
    """Devuelve una nueva pregunta CAPTCHA en JSON (llamada AJAX)."""
    from flask import jsonify
    pregunta, respuesta = generar_captcha()
    session['captcha_pregunta']  = pregunta
    session['captcha_respuesta'] = respuesta
    return jsonify({'pregunta': pregunta})


# ══════════════════════════════════════════════════════
#  MENÚ PRINCIPAL
# ══════════════════════════════════════════════════════

@app.route('/menu')
def menu():
    if 'rol' not in session:
        return redirect(url_for('login'))
    return render_template('menu.html')


# ══════════════════════════════════════════════════════
#  MÓDULO: SEDES
# ══════════════════════════════════════════════════════

@app.route('/sedes')
def sedes():
    if 'rol' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    registros = conn.execute('SELECT * FROM sedes').fetchall()
    conn.close()
    return render_template('sedes.html', registros=registros)

@app.route('/sedes/crear', methods=['POST'])
def sedes_crear():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('sedes'))
    conn = get_db()
    conn.execute('INSERT INTO sedes (nombre, tipo_institucion, ubicacion) VALUES (?,?,?)',
                 (request.form['nombre'], request.form['tipo_institucion'], request.form['ubicacion']))
    conn.commit(); conn.close()
    flash('Sede creada correctamente.', 'success')
    return redirect(url_for('sedes'))

@app.route('/sedes/editar', methods=['POST'])
def sedes_editar():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('sedes'))
    conn = get_db()
    conn.execute('UPDATE sedes SET nombre=?, tipo_institucion=?, ubicacion=? WHERE id=?',
                 (request.form['nombre'], request.form['tipo_institucion'],
                  request.form['ubicacion'], request.form['id']))
    conn.commit(); conn.close()
    flash('Sede actualizada.', 'success')
    return redirect(url_for('sedes'))

@app.route('/sedes/eliminar/<int:id>', methods=['POST'])
def sedes_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Solo el administrador puede eliminar.', 'error')
        return redirect(url_for('sedes'))
    conn = get_db()
    conn.execute('DELETE FROM sedes WHERE id=?', (id,))
    conn.commit(); conn.close()
    flash('Sede eliminada.', 'success')
    return redirect(url_for('sedes'))


# ══════════════════════════════════════════════════════
#  MÓDULO: ACTIVIDADES
# ══════════════════════════════════════════════════════

@app.route('/actividades')
def actividades_crud():
    if 'rol' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    registros = conn.execute('''
        SELECT a.*,
               (SELECT COUNT(*) FROM evidencias e WHERE e.actividad = a.nombre) AS total_evidencias
        FROM actividades a
    ''').fetchall()
    asignaturas = conn.execute('SELECT nombre FROM asignaturas ORDER BY nombre').fetchall()
    conn.close()
    return render_template('actividades.html', registros=registros, asignaturas=asignaturas)

@app.route('/actividades/crear', methods=['POST'])
def actividades_crear():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('actividades_crud'))
    conn = get_db()
    conn.execute(
        'INSERT INTO actividades (nombre, tipo, descripcion, fecha_entrega, asignatura) VALUES (?,?,?,?,?)',
        (request.form['nombre'], request.form['tipo'], request.form['descripcion'],
         request.form['fecha_entrega'], request.form['asignatura'])
    )
    conn.commit(); conn.close()
    flash('Actividad creada.', 'success')
    return redirect(url_for('actividades_crud'))

@app.route('/actividades/editar', methods=['POST'])
def actividades_editar():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('actividades_crud'))
    
    # Solo admin/docente pueden editar
    conn = get_db()
    conn.execute(
        'UPDATE actividades SET nombre=?, tipo=?, descripcion=?, fecha_entrega=?, asignatura=? WHERE id=?',
        (request.form['nombre'], request.form['tipo'], request.form['descripcion'],
         request.form['fecha_entrega'], request.form['asignatura'], request.form['id'])
    )
    conn.commit(); conn.close()
    flash('Actividad actualizada.', 'success')
    return redirect(url_for('actividades_crud'))


@app.route('/actividades/eliminar/<int:id>', methods=['POST'])
def actividades_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Solo el administrador puede eliminar.', 'error')
        return redirect(url_for('actividades_crud'))
    conn = get_db()
    conn.execute('DELETE FROM actividades WHERE id=?', (id,))
    conn.commit(); conn.close()
    flash('Actividad eliminada.', 'success')
    return redirect(url_for('actividades_crud'))


# ══════════════════════════════════════════════════════
#  MÓDULO: ASIGNATURAS
# ══════════════════════════════════════════════════════

@app.route('/asignaturas')
def asignaturas_crud():
    if 'rol' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    registros = conn.execute('''
        SELECT a.*,
               GROUP_CONCAT(r.nombre, ', ') AS responsables_nombres
        FROM asignaturas a
        LEFT JOIN responsables r ON r.asignatura_id = a.id
        GROUP BY a.id
    ''').fetchall()
    conn.close()
    return render_template('asignaturas.html', registros=registros)

@app.route('/asignaturas/crear', methods=['POST'])
def asignaturas_crear():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('asignaturas_crud'))
    conn = get_db()
    conn.execute('INSERT INTO asignaturas (nombre, docente, area_academica) VALUES (?,?,?)',
                 (request.form['nombre'], request.form['docente'], request.form['area_academica']))
    conn.commit(); conn.close()
    flash('Asignatura creada.', 'success')
    return redirect(url_for('asignaturas_crud'))

@app.route('/asignaturas/editar', methods=['POST'])
def asignaturas_editar():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('asignaturas_crud'))
    conn = get_db()
    conn.execute('UPDATE asignaturas SET nombre=?, docente=?, area_academica=? WHERE id=?',
                 (request.form['nombre'], request.form['docente'],
                  request.form['area_academica'], request.form['id']))
    conn.commit(); conn.close()
    flash('Asignatura actualizada.', 'success')
    return redirect(url_for('asignaturas_crud'))

@app.route('/asignaturas/eliminar/<int:id>', methods=['POST'])
def asignaturas_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Solo el administrador puede eliminar.', 'error')
        return redirect(url_for('asignaturas_crud'))
    conn = get_db()
    conn.execute('DELETE FROM asignaturas WHERE id=?', (id,))
    conn.commit(); conn.close()
    flash('Asignatura eliminada.', 'success')
    return redirect(url_for('asignaturas_crud'))


# ══════════════════════════════════════════════════════
#  MÓDULO: EVIDENCIAS
# ══════════════════════════════════════════════════════

@app.route('/evidencias')
def evidencias_crud():
    if 'rol' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    if session['rol'] == 'usuario':
        registros = conn.execute(
            'SELECT * FROM evidencias WHERE usuario_id=?', (session['user_id'],)
        ).fetchall()
    else:
        registros = conn.execute('SELECT * FROM evidencias').fetchall()
    actividades = conn.execute('SELECT id, nombre FROM actividades ORDER BY nombre').fetchall()
    conn.close()
    return render_template('evidencias.html', registros=registros, actividades=actividades)

import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'mp4', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/evidencias/crear', methods=['POST'])
def evidencias_crear():
    if 'rol' not in session:
        return redirect(url_for('login'))
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('evidencias_crud'))

    archivo = request.files.get('archivo')
    nombre_archivo = None

    if archivo and archivo.filename != '' and allowed_file(archivo.filename):
        nombre_archivo = secure_filename(archivo.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo))

    conn = get_db()
    conn.execute(
        'INSERT INTO evidencias (actividad, tipo_evidencia, descripcion, archivo, usuario_id) VALUES (?,?,?,?,?)',
        (request.form['actividad'], request.form['tipo_evidencia'],
         request.form['descripcion'], nombre_archivo, session['user_id'])
    )
    conn.commit(); conn.close()
    flash('Evidencia registrada.', 'success')
    return redirect(url_for('evidencias_crud'))

@app.route('/evidencias/editar', methods=['POST'])
def evidencias_editar():
    if 'rol' not in session:
        return redirect(url_for('login'))
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('evidencias_crud'))

    conn = get_db()
    archivo_actual = conn.execute(
        'SELECT archivo FROM evidencias WHERE id=?',
        (request.form['id'],)
    ).fetchone()

    nombre_archivo = archivo_actual['archivo']

    archivo = request.files.get('archivo')

    if archivo and archivo.filename != '':
        nombre_archivo = archivo.filename
        archivo.save(os.path.join('static/uploads', nombre_archivo))

    conn.execute('''
        UPDATE evidencias
        SET actividad=?,
            tipo_evidencia=?,
            descripcion=?,
            archivo=?
        WHERE id=?
    ''', (
        request.form['actividad'],
        request.form['tipo_evidencia'],
        request.form['descripcion'],
        nombre_archivo,
        request.form['id']
    ))

    conn.commit()
    conn.close()

    flash('Evidencia actualizada correctamente', 'success')

    return redirect(url_for('evidencias_crud'))

# ══════════════════════════════════════════════════════
#  MÓDULO: RESPONSABLES
# ══════════════════════════════════════════════════════

@app.route('/responsables')
def responsables_crud():
    if 'rol' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    registros = conn.execute('''
        SELECT r.*, a.nombre AS asignatura_nombre
        FROM responsables r
        LEFT JOIN asignaturas a ON a.id = r.asignatura_id
    ''').fetchall()
    asignaturas = conn.execute('SELECT id, nombre FROM asignaturas ORDER BY nombre').fetchall()
    conn.close()
    return render_template('responsables.html', registros=registros, asignaturas=asignaturas)

@app.route('/responsables/crear', methods=['POST'])
def responsables_crear():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('responsables_crud'))
    conn = get_db()
    conn.execute('INSERT INTO responsables (nombre, cargo, asignatura_id) VALUES (?,?,?)',
                 (request.form['nombre'], request.form['cargo'], request.form.get('asignatura_id') or None))
    conn.commit(); conn.close()
    flash('Responsable creado.', 'success')
    return redirect(url_for('responsables_crud'))

@app.route('/responsables/editar', methods=['POST'])
def responsables_editar():
    if solo_lectura():
        flash('No tienes permiso para realizar esta acción.', 'error')
        return redirect(url_for('responsables_crud'))
    conn = get_db()
    conn.execute('UPDATE responsables SET nombre=?, cargo=?, asignatura_id=? WHERE id=?',
                 (request.form['nombre'], request.form['cargo'],
                  request.form.get('asignatura_id') or None, request.form['id']))
    conn.commit(); conn.close()
    flash('Responsable actualizado.', 'success')
    return redirect(url_for('responsables_crud'))

@app.route('/responsables/eliminar/<int:id>', methods=['POST'])
def responsables_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Solo el administrador puede eliminar.', 'error')
        return redirect(url_for('responsables_crud'))
    conn = get_db()
    conn.execute('DELETE FROM responsables WHERE id=?', (id,))
    conn.commit(); conn.close()
    flash('Responsable eliminado.', 'success')
    return redirect(url_for('responsables_crud'))


# ══════════════════════════════════════════════════════
#  ARRANQUE
# ══════════════════════════════════════════════════════

# Inicializa la base de datos tanto en Render como en ejecución local
init_db()

if __name__ == '__main__':
    app.run(debug=True)