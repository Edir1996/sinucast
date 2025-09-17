from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import shutil
import re
from datetime import datetime, timedelta
import stat
import subprocess
import time
import json
from threading import Thread, Lock
import mercadopago

app = Flask(__name__)

# --- Configurações ---
app.config['SECRET_KEY'] = 'sua_chave_secreta_super_segura_troque_isso'
app.config['UPLOAD_FOLDER'] = 'static/logos'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 # Limite de 4MB para logos
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- Configuração do MySQL ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'sinucast_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# --- Configurações Globais de Vídeo ---
FFMPEG_PATH = 'ffmpeg'
MIN_RECORDING_DURATION_SECONDS = 30
MAX_RECORDING_DURATION_SECONDS = 60 * 20
VIDEO_EXPIRATION_DAYS = 7
MAX_VIDEOS_PER_USER = 5

# --- Estado e Locks de Vídeo ---
recording_processes = {}
process_lock = Lock()


def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def remove_readonly(func, path, _):
    """Limpa o bit somente leitura e tenta novamente a remoção"""
    os.chmod(path, stat.S_IWRITE)
    func(path)

# --- FUNÇÕES AUXILIARES DE VÍDEO ---

def track_event(client_id, user_identifier, event_type, details=''):
    """Registra um evento de análise no banco de dados."""
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO client_analytics (client_id, user_uid, event_type, details) VALUES (%s, %s, %s, %s)",
            (client_id, user_identifier, event_type, details)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        print(f"Erro ao rastrear evento '{event_type}' para client_id {client_id}: {e}")

def convert_to_mp4(ts_file_path, mp4_file_path):
    """Converte um arquivo de vídeo .ts para .mp4 usando ffmpeg."""
    try:
        cmd = [FFMPEG_PATH, '-i', ts_file_path, '-c', 'copy', '-y', mp4_file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0 and os.path.exists(mp4_file_path):
            os.remove(ts_file_path)
            print(f"Vídeo convertido: {mp4_file_path}")
        else:
            print(f"Erro na conversão: {result.stderr}")
            if os.path.exists(ts_file_path): os.remove(ts_file_path)
    except Exception as e:
        print(f"Erro excepcional na conversão: {e}")


# --- ROTAS PRINCIPAIS ---

@app.route('/')
def landing_page():
    """ Rota principal que exibe a landing page do serviço. """
    return render_template('landing_page.html')

@app.route('/<establishment_slug>')
def establishment_page(establishment_slug):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM clients WHERE REPLACE(LOWER(establishment_name), ' ', '') = %s", [establishment_slug.lower()])
    client = cur.fetchone()
    
    if not client:
        return render_template('site_offline.html', message="Estabelecimento não encontrado."), 404

    if client['subscription_status'] in ['pending_payment', 'canceled']:
        return render_template('site_offline.html', message="Sistema temporariamente indisponível. Contate o administrador.")

    cur.execute("SELECT camera_name, camera_url FROM cameras WHERE client_id = %s", (client['id'],))
    cameras = cur.fetchall()
    cur.close()
    
    folder_name = client['establishment_name'].replace(' ', '')
    
    return render_template('index.html', cameras=cameras, establishment_username=folder_name, client_id=client['id'], client=client)


@app.route('/site_offline')
def site_offline():
    message = request.args.get('message', 'Ocorreu um problema.')
    return render_template('site_offline.html', message=message)

# --- ROTAS DE AUTENTICAÇÃO ---

@app.route('/admin')
def admin_redirect():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    if 'client_logged_in' in session:
        return redirect(url_for('client_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cur = mysql.connection.cursor()
        
        cur.execute("SELECT * FROM admins WHERE username = %s", [username])
        admin = cur.fetchone()
        if admin and admin['password'] == password:
            session['admin_logged_in'] = True
            session['admin_username'] = admin['username']
            session['toast'] = {'message': 'Login de administrador bem-sucedido!', 'type': 'success'}
            cur.close()
            return redirect(url_for('admin_dashboard'))

        cur.execute("SELECT * FROM clients WHERE username = %s", [username])
        client = cur.fetchone()
        cur.close()
        if client and check_password_hash(client['password'], password):
            session['client_logged_in'] = True
            session['client_id'] = client['id']
            session['client_username'] = client['username']
            session['establishment_name'] = client['establishment_name']
            session['toast'] = {'message': f'Bem-vindo, {client["establishment_name"]}!', 'type': 'success'}
            return redirect(url_for('client_dashboard'))

        session['toast'] = {'message': 'Usuário ou senha inválidos.', 'type': 'error'}
        return redirect(url_for('login'))
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session['toast'] = {'message': 'Você foi desconectado.', 'type': 'info'}
    return redirect(url_for('login'))

# --- ROTAS DO PAINEL DE ADMIN ---

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    
    cur.execute("SELECT subscription_status, price FROM clients")
    all_clients_stats = cur.fetchall()

    total_clients = len(all_clients_stats)
    active_clients = sum(1 for client in all_clients_stats if client['subscription_status'] == 'active')
    
    mrr = sum(client['price'] for client in all_clients_stats if client['subscription_status'] == 'active' and client['price'])

    stats = {
        'total_clients': total_clients,
        'active_clients': active_clients,
        'mrr': mrr
    }
    
    cur.close()
    
    return render_template('admin_dashboard.html', stats=stats)

@app.route('/admin/clients')
def admin_clients():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT c.*, p.name AS plan_name 
        FROM clients c 
        LEFT JOIN plans p ON c.plan_id = p.id 
        ORDER BY c.created_at DESC
    """)
    clients = cur.fetchall()
    cur.execute("SELECT * FROM plans WHERE is_active = 1 ORDER BY name")
    plans = cur.fetchall()
    cur.close()
    
    return render_template('admin_clients.html', clients=clients, plans=plans)

@app.route('/admin/add_client', methods=['POST'])
def add_client():
    if 'admin_logged_in' not in session:
        return jsonify({'success': False, 'message': 'Não autorizado'}), 403

    establishment = request.form['establishment_name']
    username = request.form['username']
    password = request.form['password']
    plan_id = request.form['plan_id']
    camera_names = request.form.getlist('camera_name[]')
    camera_urls = request.form.getlist('camera_url[]')

    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        session['toast'] = {'message': 'Usuário inválido. Use apenas letras, números e os caracteres "_", "-", ".".', 'type': 'error'}
        return redirect(url_for('admin_clients'))
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT name, price FROM plans WHERE id = %s", [plan_id])
        plan = cur.fetchone()
        if not plan:
            session['toast'] = {'message': 'Plano selecionado é inválido.', 'type': 'error'}
            return redirect(url_for('admin_clients'))

        hashed_password = generate_password_hash(password)
        next_billing_date = datetime.now() + timedelta(days=30)
        
        cur.execute("INSERT INTO clients (establishment_name, username, password, plan_id, plan_type, price, next_billing_date, subscription_status, payment_status) VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', 'paid')", 
                    (establishment, username, hashed_password, plan_id, plan['name'], plan['price'], next_billing_date))
        client_id = cur.lastrowid

        for name, url in zip(camera_names, camera_urls):
            if name and url:
                cur.execute("INSERT INTO cameras (client_id, camera_name, camera_url) VALUES (%s, %s, %s)", (client_id, name, url))

        mysql.connection.commit()
        
        folder_name = establishment.replace(' ', '')
        client_video_path = os.path.join('static', 'videos', folder_name)
        os.makedirs(client_video_path, exist_ok=True)
        
        session['toast'] = {'message': f'Cliente "{establishment}" criado com sucesso!', 'type': 'success'}
    except Exception as e:
        mysql.connection.rollback()
        session['toast'] = {'message': f'Erro ao criar cliente: {e}', 'type': 'error'}
    finally:
        cur.close()

    return redirect(url_for('admin_clients'))

@app.route('/admin/update_client/<int:client_id>', methods=['POST'])
def update_client(client_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))

    try:
        new_establishment_name = request.form['establishment_name']
        password = request.form.get('password')
        status = request.form['subscription_status']
        plan_id = request.form['plan_id']
        billing_date = request.form['next_billing_date']
        
        cur = mysql.connection.cursor()

        cur.execute("SELECT establishment_name FROM clients WHERE id = %s", [client_id])
        old_client_data = cur.fetchone()
        old_establishment_name = old_client_data['establishment_name'] if old_client_data else ''

        cur.execute("SELECT name, price FROM plans WHERE id = %s", [plan_id])
        plan = cur.fetchone()
        if not plan:
            session['toast'] = {"message": "Plano inválido.", "type": "error"}
            return redirect(url_for('admin_clients'))

        billing_date_db = billing_date if billing_date else None
        new_payment_status = 'paid' if status == 'active' else 'pending'

        query_parts = [
            "establishment_name = %s", "subscription_status = %s", "plan_id = %s", "plan_type = %s",
            "price = %s", "next_billing_date = %s", "payment_status = %s"
        ]
        params = [
            new_establishment_name, status, plan_id, plan['name'], plan['price'],
            billing_date_db, new_payment_status
        ]

        if password:
            hashed_password = generate_password_hash(password)
            query_parts.append("password = %s")
            params.append(hashed_password)
        
        params.append(client_id)
        
        query = f"UPDATE clients SET {', '.join(query_parts)} WHERE id = %s"
        
        cur.execute(query, tuple(params))
        mysql.connection.commit()

        old_folder_name = old_establishment_name.replace(' ', '')
        new_folder_name = new_establishment_name.replace(' ', '')
        if old_folder_name != new_folder_name:
            old_path = os.path.join('static', 'videos', old_folder_name)
            new_path = os.path.join('static', 'videos', new_folder_name)
            if os.path.exists(old_path):
                os.rename(old_path, new_path)

        cur.close()
        session['toast'] = {'message': 'Dados do cliente atualizados com sucesso.', 'type': 'success'}
    except Exception as e:
        session['toast'] = {'message': f'Erro ao atualizar cliente: {e}', 'type': 'error'}

    return redirect(url_for('admin_clients'))

@app.route('/admin/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    if 'admin_logged_in' not in session: return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT establishment_name FROM clients WHERE id = %s", [client_id])
        client = cur.fetchone()
        if client:
            establishment_name = client['establishment_name']
            cur.execute("DELETE FROM cameras WHERE client_id = %s", [client_id])
            cur.execute("DELETE FROM clients WHERE id = %s", [client_id])
            mysql.connection.commit()
            
            folder_name = establishment_name.replace(' ', '')
            client_video_path = os.path.join('static', 'videos', folder_name)
            if os.path.exists(client_video_path):
                shutil.rmtree(client_video_path, onerror=remove_readonly)
            
            session['toast'] = {'message': 'Cliente e seus dados foram excluídos com sucesso.', 'type': 'success'}
    except Exception as e:
        session['toast'] = {'message': f'Erro ao excluir cliente: {e}', 'type': 'error'}
    finally:
        cur.close()
    return redirect(url_for('admin_clients'))

# --- ROTAS DE CONFIGURAÇÕES DE PLANOS ---

@app.route('/admin/settings')
def admin_settings():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM plans ORDER BY name")
    plans = cur.fetchall()
    cur.close()
    return render_template('admin_settings.html', plans=plans)

@app.route('/admin/add_plan', methods=['POST'])
def add_plan():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    name = request.form['name']
    price = request.form['price']
    
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO plans (name, price) VALUES (%s, %s)", (name, price))
    mysql.connection.commit()
    cur.close()
    session['toast'] = {'message': 'Novo plano adicionado com sucesso!', 'type': 'success'}
    return redirect(url_for('admin_settings'))

@app.route('/admin/update_plan/<int:plan_id>', methods=['POST'])
def update_plan(plan_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
        
    name = request.form['name']
    price = request.form['price']
    
    cur = mysql.connection.cursor()
    cur.execute("UPDATE plans SET name = %s, price = %s WHERE id = %s", (name, price, plan_id))
    mysql.connection.commit()
    cur.close()
    session['toast'] = {'message': 'Plano atualizado com sucesso!', 'type': 'success'}
    return redirect(url_for('admin_settings'))

@app.route('/admin/delete_plan/<int:plan_id>', methods=['POST'])
def delete_plan(plan_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("UPDATE plans SET is_active = 0 WHERE id = %s", [plan_id])
    mysql.connection.commit()
    cur.close()
    session['toast'] = {'message': 'Plano desativado com sucesso.', 'type': 'success'}
    return redirect(url_for('admin_settings'))

# --- ROTAS DO CLIENTE ---
@app.route('/client/dashboard')
def client_dashboard():
    if 'client_logged_in' not in session:
        session['toast'] = {'message': 'Faça login para acessar esta página.', 'type': 'error'}
        return redirect(url_for('login'))

    client_id = session['client_id']
    cur = mysql.connection.cursor()

    try:
        cur.execute("SELECT COUNT(DISTINCT user_uid) as total_users FROM client_analytics WHERE client_id = %s", [client_id])
        total_users_result = cur.fetchone()
        total_users = total_users_result['total_users'] if total_users_result else 0

        cur.execute("SELECT COUNT(*) as total_recordings FROM client_analytics WHERE client_id = %s AND event_type = 'recording_started'", [client_id])
        total_recordings_result = cur.fetchone()
        total_recordings = total_recordings_result['total_recordings'] if total_recordings_result else 0
        
        cur.execute("SELECT COUNT(*) as total_downloads FROM client_analytics WHERE client_id = %s AND event_type = 'download_completed'", [client_id])
        total_downloads_result = cur.fetchone()
        total_downloads = total_downloads_result['total_downloads'] if total_downloads_result else 0

        stats = {
            'total_users': total_users,
            'total_recordings': total_recordings,
            'total_downloads': total_downloads
        }
        
        return render_template('client_dashboard.html', stats=stats)
    except Exception as e:
        print(f"Erro ao buscar estatísticas do cliente: {e}")
        stats = {'total_users': 0, 'total_recordings': 0, 'total_downloads': 0}
        return render_template('client_dashboard.html', stats=stats)
    finally:
        cur.close()

@app.route('/client/settings', methods=['GET', 'POST'])
def client_settings():
    if 'client_logged_in' not in session:
        return redirect(url_for('login'))

    client_id = session['client_id']
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        # --- Seção de Personalização ---
        site_title = request.form.get('site_title')
        logo_shape = request.form.get('logo_shape')
        logo_file = request.files.get('logo_file')
        
        # --- Seção de Pagamentos ---
        payment_mode = 'paid' if 'payment_mode' in request.form else 'free'
        video_price = request.form.get('video_price')
        allow_one_free_video = 'allow_one_free_video' in request.form
        mercado_pago_token = request.form.get('mercado_pago_token')

        # --- Atualização do Banco de Dados ---
        update_query = """
            UPDATE clients SET 
            site_title = %s, 
            logo_shape = %s,
            payment_mode = %s,
            video_price = %s,
            allow_one_free_video = %s,
            mercado_pago_token = %s
        """
        params = [
            site_title, 
            logo_shape, 
            payment_mode,
            video_price if payment_mode == 'paid' else None,
            allow_one_free_video,
            mercado_pago_token
        ]

        if logo_file and allowed_file(logo_file.filename):
            filename = secure_filename(f"logo_{client_id}_{int(time.time())}.{logo_file.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            cur.execute("SELECT logo_url FROM clients WHERE id = %s", [client_id])
            old_logo = cur.fetchone()
            if old_logo and old_logo['logo_url']:
                old_logo_path = os.path.join(os.getcwd(), old_logo['logo_url'].lstrip('/'))
                if os.path.exists(old_logo_path):
                    try:
                        os.remove(old_logo_path)
                    except OSError as e:
                        print(f"Error deleting old logo: {e}")

            logo_file.save(filepath)
            logo_url = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')
            update_query += ", logo_url = %s"
            params.append(logo_url)
        
        update_query += " WHERE id = %s"
        params.append(client_id)

        cur.execute(update_query, tuple(params))
        mysql.connection.commit()
        session['toast'] = {'message': 'Configurações salvas com sucesso!', 'type': 'success'}
        cur.close()
        return redirect(url_for('client_settings'))

    cur.execute("SELECT * FROM clients WHERE id = %s", [client_id])
    client_data = cur.fetchone()
    cur.close()
    return render_template('client_settings.html', client=client_data)


@app.route('/client/logout')
def client_logout():
    session.pop('client_logged_in', None)
    session.pop('client_id', None)
    session.pop('client_username', None)
    session.pop('establishment_name', None)
    session['toast'] = {'message': 'Você foi desconectado.', 'type': 'info'}
    return redirect(url_for('login'))

# --- ROTAS DA API DE VÍDEO E ANÁLISE ---

@app.route('/api/mercado_pago_webhook', methods=['POST'])
def mercado_pago_webhook():
    data = request.get_json()
    print(f"Webhook recebido: {data}")

    if data and data.get('type') == 'payment':
        payment_id = data['data']['id']
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT client_id FROM video_payments WHERE payment_id_mp = %s", (payment_id,))
        payment_record = cur.fetchone()
        
        if not payment_record:
            cur.close()
            return jsonify({'status': 'ok'}), 200

        client_id = payment_record['client_id']
        cur.execute("SELECT mercado_pago_token FROM clients WHERE id = %s", (client_id,))
        client = cur.fetchone()

        if not client or not client['mercado_pago_token']:
            cur.close()
            return jsonify({'status': 'client not configured'}), 400

        try:
            sdk = mercadopago.SDK(client['mercado_pago_token'])
            payment_info = sdk.payment().get(payment_id)
            if payment_info["status"] == 200 and payment_info["response"]["status"] == 'approved':
                cur.execute("UPDATE video_payments SET status = 'approved' WHERE payment_id_mp = %s", (payment_id,))
                mysql.connection.commit()
        except Exception as e:
            print(f"Erro ao processar webhook: {e}")
        finally:
            cur.close()

    return jsonify({'status': 'ok'}), 200


@app.route('/api/create_payment', methods=['POST'])
def create_payment():
    data = request.get_json()
    client_id = data.get('clientId')
    user_id = data.get('userId')
    video_id = data.get('videoId')

    if not all([client_id, user_id, video_id]):
        return jsonify({'success': False, 'message': 'Dados insuficientes.'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT video_price, mercado_pago_token FROM clients WHERE id = %s", [client_id])
    client = cur.fetchone()
    cur.close()

    if not client or not client['video_price'] or not client['mercado_pago_token']:
        return jsonify({'success': False, 'message': 'Configuração de pagamento incompleta.'}), 500

    try:
        sdk = mercadopago.SDK(client['mercado_pago_token'])
        payment_data = {
            "transaction_amount": float(client['video_price']),
            "description": f"Download do vídeo: {video_id}",
            "payment_method_id": "pix",
            "payer": {
                "email": f"user_{user_id}@sinucast.com",
            }
        }
        payment_response = sdk.payment().create(payment_data)
        payment = payment_response["response"]
        
        if payment_response["status"] == 201:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO video_payments (client_id, user_uid, video_filename, payment_id_mp, status) VALUES (%s, %s, %s, %s, %s)",
                (client_id, user_id, video_id, payment['id'], 'pending')
            )
            mysql.connection.commit()
            cur.close()

            return jsonify({
                'success': True,
                'paymentId': payment['id'],
                'qrCode': payment['point_of_interaction']['transaction_data']['qr_code_base64'],
                'qrCodeCopy': payment['point_of_interaction']['transaction_data']['qr_code']
            })
        else:
            return jsonify({'success': False, 'message': 'Erro ao criar pagamento no Mercado Pago.'}), 500

    except Exception as e:
        print(f"Erro na API do Mercado Pago: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
        
@app.route('/api/check_payment_status', methods=['GET'])
def check_payment_status():
    payment_id = request.args.get('paymentId')
    client_id = request.args.get('clientId')

    if not all([payment_id, client_id]):
        return jsonify({'status': 'error', 'message': 'Dados insuficientes.'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT mercado_pago_token FROM clients WHERE id = %s", [client_id])
    client = cur.fetchone()
    cur.close()

    if not client or not client['mercado_pago_token']:
        return jsonify({'status': 'error', 'message': 'Cliente não configurado.'}), 500

    try:
        sdk = mercadopago.SDK(client['mercado_pago_token'])
        payment_info = sdk.payment().get(payment_id)
        
        if payment_info["status"] == 200:
            status = payment_info["response"]["status"]
            if status == 'approved':
                cur = mysql.connection.cursor()
                cur.execute("UPDATE video_payments SET status = 'approved' WHERE payment_id_mp = %s", [payment_id])
                mysql.connection.commit()
                cur.close()
            return jsonify({'status': status})
        else:
            return jsonify({'status': 'pending'})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/use_free_download', methods=['POST'])
def use_free_download():
    data = request.get_json()
    client_id = data.get('clientId')
    user_id = data.get('userId')
    
    if not all([client_id, user_id]):
        return jsonify({'success': False, 'message': 'Dados insuficientes.'}), 400
        
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO free_downloads (client_id, user_uid) VALUES (%s, %s)", (client_id, user_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Não foi possível registrar o download gratuito.'}), 500


@app.route('/api/track_user', methods=['POST'])
def track_user():
    data = request.get_json()
    visitor_id = data.get('visitorId')
    client_id = data.get('clientId')

    if not all([visitor_id, client_id]):
        return jsonify({'success': False, 'message': 'Dados insuficientes.'}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM client_analytics WHERE client_id = %s AND user_uid = %s AND event_type = 'user_visit' LIMIT 1", (client_id, visitor_id))
        exists = cur.fetchone()
        
        if not exists:
            track_event(client_id, visitor_id, 'user_visit')
        
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Erro ao rastrear usuário: {e}")
        return jsonify({'success': False, 'message': 'Erro interno do servidor.'}), 500

@app.route('/api/check_camera', methods=['POST'])
def check_camera():
    rtsp_url = request.json.get('camera_url')
    if not rtsp_url: return jsonify({'success': False, 'message': 'URL da câmera não fornecida.'}), 400
    try:
        cmd = ['ffprobe', '-v', 'error', '-rtsp_transport', 'tcp', '-select_streams', 'v:0', '-show_entries', 'stream=codec_type', '-of', 'json', rtsp_url]
        subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        return jsonify({'success': True, 'status': 'online'})
    except Exception as e:
        return jsonify({'success': False, 'status': 'offline', 'message': f'Câmera inacessível: {e}'})

@app.route('/api/check_recording_status', methods=['GET'])
def check_recording_status():
    user_id = request.args.get('user_id')
    establishment = request.args.get('establishment')

    if not all([user_id, establishment]):
        return jsonify({'isRecording': False, 'message': 'Dados insuficientes.'}), 400

    process_key = f"{establishment}_{user_id}"
    with process_lock:
        if process_key in recording_processes:
            rec_info = recording_processes[process_key]
            return jsonify({
                'isRecording': True,
                'startTime': rec_info['start_time'],
                'cameraName': rec_info.get('camera_name', '')
            })
        else:
            return jsonify({'isRecording': False})

@app.route('/api/start_recording', methods=['POST'])
def start_recording():
    data = request.get_json()
    user_id = data.get('userId')
    establishment = data.get('establishment')
    rtsp_url = data.get('camera_url')
    camera_name = data.get('camera_name')
    client_id = data.get('clientId')

    if not all([user_id, establishment, rtsp_url, camera_name, client_id]):
        return jsonify({'success': False, 'message': 'Dados insuficientes para iniciar a gravação.'}), 400

    output_dir = os.path.join(os.path.dirname(__file__), 'static', 'videos', establishment)
    if not os.path.exists(output_dir):
        return jsonify({'success': False, 'message': 'Diretório do estabelecimento não encontrado.'}), 404

    user_videos = [f for f in os.listdir(output_dir) if f.startswith(user_id) and f.endswith('.mp4')]
    if len(user_videos) >= MAX_VIDEOS_PER_USER:
        return jsonify({'success': False, 'message': f'Limite de {MAX_VIDEOS_PER_USER} vídeos por usuário atingido.'}), 403

    process_key = f"{establishment}_{user_id}"
    with process_lock:
        if process_key in recording_processes:
            return jsonify({'success': False, 'message': 'Gravação já em andamento.'}), 409

        timestamp_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"{user_id}_{timestamp_str}"
        ts_path = os.path.join(output_dir, f"{filename}.ts")
        
        cmd = [
            FFMPEG_PATH, '-rtsp_transport', 'tcp', '-i', rtsp_url,
            '-t', str(MAX_RECORDING_DURATION_SECONDS),
            '-c:v', 'copy', '-c:a', 'aac', '-ar', '44100', '-y', ts_path
        ]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)
            if process.poll() is not None:
                _, stderr = process.communicate()
                raise RuntimeError(f"Falha ao iniciar FFmpeg: {stderr.decode('utf-8', errors='ignore')}")
            
            recording_processes[process_key] = {
                'process': process,
                'ts_file': ts_path,
                'start_time': int(time.time() * 1000),
                'camera_name': camera_name
            }
            track_event(client_id, user_id, 'recording_started', json.dumps({'camera': camera_name}))
            return jsonify({'success': True, 'startTime': recording_processes[process_key]['start_time']})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/stop_recording', methods=['POST'])
def stop_recording():
    data = request.get_json()
    user_id = data.get('userId')
    establishment = data.get('establishment')
    start_time = data.get('startTime')
    process_key = f"{establishment}_{user_id}"

    with process_lock:
        if process_key not in recording_processes:
            return jsonify({'success': False, 'message': 'Nenhuma gravação encontrada.'}), 404
        
        rec_info = recording_processes.pop(process_key)
        process, ts_file = rec_info['process'], rec_info['ts_file']
        
        if (int(time.time() * 1000) - start_time) < MIN_RECORDING_DURATION_SECONDS * 1000:
            process.terminate()
            time.sleep(1)
            if os.path.exists(ts_file): os.remove(ts_file)
            return jsonify({'success': False, 'message': f'Gravação deve ter no mínimo {MIN_RECORDING_DURATION_SECONDS}s.'}), 400

        process.terminate()
        process.wait()

    mp4_path = ts_file.replace('.ts', '.mp4')
    Thread(target=convert_to_mp4, args=(ts_file, mp4_path)).start()
    return jsonify({'success': True, 'message': 'Processando vídeo...'})

@app.route('/api/track_download', methods=['POST'])
def track_download():
    data = request.get_json()
    user_id = data.get('userId')
    client_id = data.get('clientId')
    filename = data.get('filename')

    if not all([user_id, client_id, filename]):
        return jsonify({'success': False, 'message': 'Dados insuficientes.'}), 400

    track_event(client_id, user_id, 'download_completed', json.dumps({'filename': filename}))
    return jsonify({'success': True})

@app.route('/api/get_videos')
def get_videos():
    user_id = request.args.get('user_id')
    establishment = request.args.get('establishment')
    client_id = request.args.get('clientId')

    if not all([user_id, establishment, client_id]):
        return jsonify({'error': 'Dados insuficientes.'}), 400

    output_dir = os.path.join(os.path.dirname(__file__), 'static', 'videos', establishment)
    if not os.path.exists(output_dir): return jsonify([])
    
    cur = mysql.connection.cursor()
    # Verifica pagamentos aprovados
    cur.execute("SELECT video_filename FROM video_payments WHERE client_id = %s AND user_uid = %s AND status = 'approved'", (client_id, user_id))
    paid_videos_result = cur.fetchall()
    paid_videos = {row['video_filename'] for row in paid_videos_result}
    
    # Verifica se já usou o download gratuito
    cur.execute("SELECT id FROM free_downloads WHERE client_id = %s AND user_uid = %s", (client_id, user_id))
    has_used_free_download = cur.fetchone() is not None
    cur.close()

    video_files = [f for f in os.listdir(output_dir) if f.startswith(user_id) and f.endswith('.mp4')]
    videos_list = []
    for filename in video_files:
        try:
            timestamp_str = '_'.join(filename.replace('.mp4', '').split('_')[1:])
            created_at = datetime.strptime(timestamp_str, '%Y-%m-%d_%H-%M-%S')
        except:
            created_at = datetime.fromtimestamp(os.path.getctime(os.path.join(output_dir, filename)))
        
        videos_list.append({
            'id': filename,
            'createdAt': created_at.isoformat(),
            'path': url_for('static', filename=f"videos/{establishment}/{filename}"),
            'isPaid': filename in paid_videos
        })
    
    videos_list.sort(key=lambda x: x['createdAt'], reverse=True)
    return jsonify({'videos': videos_list, 'hasUsedFreeDownload': has_used_free_download})

@app.route('/api/delete_video', methods=['POST'])
def delete_video():
    data = request.get_json()
    filename = data.get('filename')
    establishment = data.get('establishment')
    if not all([filename, establishment]):
        return jsonify({'success': False, 'message': 'Dados insuficientes.'}), 400

    video_path = os.path.join(os.path.dirname(__file__), 'static', 'videos', establishment, filename)
    if os.path.exists(video_path):
        os.remove(video_path)
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Vídeo não encontrado.'}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

