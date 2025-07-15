from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Database connection
def get_db_connection():
    try:
        # Use the provided PostgreSQL database URL
        database_url = "postgresql://mrsharabi_db_user:WIA9WtFAu8Og5bSE2YeIDNcBSpvCpWha@dpg-d1p96uk9c44c738d3050-a.oregon-postgres.render.com/mrsharabi_db"
        conn = psycopg2.connect(database_url)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# Initialize database tables
def init_db():
    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS conversations (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                sender_type VARCHAR(10) NOT NULL CHECK (sender_type IN ('user', 'admin')),
                sender_name VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_blocks (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                blocked_until TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_conversations (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS premium_applications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                premium_status VARCHAR(20) DEFAULT 'pending',
                premium_applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                premium_approved_at TIMESTAMP NULL
            )
        ''')

        conn.commit()
        cur.close()
        conn.close()

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/auth')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([name, username, email, password]):
        return jsonify({'success': False, 'message': 'All fields are required'})

    # Validate username (no capital letters)
    if username != username.lower():
        return jsonify({'success': False, 'message': 'Username must be in lowercase only'})

    # Validate email domain
    allowed_domains = ['@gmail.com', '@outlook.com', '@hotmail.com', '@yahoo.com']
    if not any(email.lower().endswith(domain) for domain in allowed_domains):
        return jsonify({'success': False, 'message': 'Email must be from gmail.com, outlook.com, hotmail.com, or yahoo.com'})

    # Validate password
    import re
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'})
    if not re.search(r'[A-Z]', password):
        return jsonify({'success': False, 'message': 'Password must contain at least 1 uppercase letter'})
    if not re.search(r'\d', password):
        return jsonify({'success': False, 'message': 'Password must contain at least 1 number'})
    if not re.search(r'[@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return jsonify({'success': False, 'message': 'Password must contain at least 1 special character (@#$% etc.)'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'})

    try:
        cur = conn.cursor()
        hashed_password = generate_password_hash(password)

        cur.execute('''
            INSERT INTO users (name, username, email, password, status)
            VALUES (%s, %s, %s, %s, 'pending')
        ''', (name, username, email, hashed_password))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Signup successful! Please wait for admin approval.'})
    except psycopg2.IntegrityError:
        return jsonify({'success': False, 'message': 'Username or email already exists'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'})

    cur = conn.cursor()
    cur.execute('SELECT id, password, status FROM users WHERE username = %s', (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and check_password_hash(user[1], password):
        if user[2] == 'approved':
            session['user_id'] = user[0]
            session['username'] = username
            return jsonify({'success': True, 'message': 'Login successful'})
        else:
            return jsonify({'success': False, 'message': 'Account pending approval'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/admin-login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Hardcoded admin credentials
    if username == 'admin' and password == 'admin':
        session['admin'] = True
        return jsonify({'success': True, 'message': 'Admin login successful'})
    else:
        return jsonify({'success': False, 'message': 'Invalid admin credentials'})

@app.route('/admin-login-page')
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/admin')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/user-approval')
def user_approval():
    if not session.get('admin'):
        return redirect(url_for('index'))
    return render_template('user_approval.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/tools')
def tools():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('tools.html', username=session.get('username', 'User'))

@app.route('/fb-tools')
def fb_tools():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('fb_tools.html', username=session.get('username', 'User'))

@app.route('/wp-tools')
def wp_tools():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('wp_tools.html', username=session.get('username', 'User'))

@app.route('/hacking-tools')
def hacking_tools():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('hacking_tools.html', username=session.get('username', 'User'))

@app.route('/other-tools')
def other_tools():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('other_tools.html', username=session.get('username', 'User'))

@app.route('/uptime')
def uptime():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('uptime.html')

@app.route('/api/users/<status>')
def get_users(status):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()

    if status == 'all':
        cur.execute('SELECT id, name, username, email, password, status, created_at FROM users ORDER BY created_at DESC')
    else:
        cur.execute('SELECT id, name, username, email, password, status, created_at FROM users WHERE status = %s ORDER BY created_at DESC', (status,))

    users = cur.fetchall()
    cur.close()
    conn.close()

    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'name': user[1],
            'username': user[2],
            'email': user[3],
            'password': '********',  # Hide actual password for security
            'status': user[5],
            'created_at': user[6].strftime('%Y-%m-%d %H:%M:%S') if user[6] else ''
        })

    return jsonify(user_list)

@app.route('/api/users/<int:user_id>/status', methods=['PUT'])
def update_user_status(user_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    status = data.get('status')

    if status not in ['approved', 'rejected', 'pending']:
        return jsonify({'error': 'Invalid status'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()
    cur.execute('UPDATE users SET status = %s WHERE id = %s', (status, user_id))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True, 'message': f'User status updated to {status}'})

@app.route('/user-conversation')
def user_conversation():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('user_conversation.html')

@app.route('/messages')
def messages():
    if not session.get('admin'):
        return redirect(url_for('index'))
    return render_template('messages.html')

@app.route('/api/conversation')
def get_user_conversation():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session.get('user_id')
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()

    # Check if user is blocked
    cur.execute('''
        SELECT blocked_until FROM user_blocks 
        WHERE user_id = %s AND blocked_until > CURRENT_TIMESTAMP
        ORDER BY blocked_until DESC LIMIT 1
    ''', (user_id,))

    block_info = cur.fetchone()
    user_status = 'blocked' if block_info else 'active'

    cur.execute('''
        SELECT content, sender_type, sender_name, created_at
        FROM conversations 
        WHERE user_id = %s 
        ORDER BY created_at ASC
    ''', (user_id,))

    messages = cur.fetchall()
    cur.close()
    conn.close()

    message_list = []
    for message in messages:
        message_list.append({
            'content': message[0],
            'sender_type': message[1],
            'sender_name': message[2],
            'created_at': message[3].strftime('%Y-%m-%d %H:%M:%S') if message[3] else ''
        })

    return jsonify({
        'success': True,
        'user_id': user_id,
        'status': user_status,
        'messages': message_list
    })

@app.route('/api/send-message', methods=['POST'])
def send_message():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session.get('user_id')

    # Check if user is blocked
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()
    cur.execute('''
        SELECT blocked_until FROM user_blocks 
        WHERE user_id = %s AND blocked_until > CURRENT_TIMESTAMP
        ORDER BY blocked_until DESC LIMIT 1
    ''', (user_id,))

    block_info = cur.fetchone()
    if block_info:
        cur.close()
        conn.close()
        return jsonify({'success': False, 'message': 'You are temporarily blocked from sending messages'})

    data = request.json
    content = data.get('content', '').strip()

    if not content:
        cur.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Message content is required'})

    username = session.get('username')

    try:
        cur.execute('''
            INSERT INTO conversations (user_id, content, sender_type, sender_name)
            VALUES (%s, %s, 'user', %s)
        ''', (user_id, content, username))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Message sent successfully'})
    except Exception as e:
        cur.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Failed to send message'})

@app.route('/api/admin/conversations')
def get_admin_conversations():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()
    cur.execute('''
        SELECT DISTINCT u.id, u.name, u.username,
               (SELECT content FROM conversations c WHERE c.user_id = u.id ORDER BY c.created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM conversations c WHERE c.user_id = u.id ORDER BY c.created_at DESC LIMIT 1) as last_message_time,
               CASE 
                   WHEN EXISTS (SELECT 1 FROM user_blocks ub WHERE ub.user_id = u.id AND ub.blocked_until > CURRENT_TIMESTAMP) 
                   THEN 'blocked' 
                   ELSE 'active' 
               END as status
        FROM users u
        WHERE u.id IN (SELECT DISTINCT user_id FROM conversations)
        ORDER BY last_message_time DESC
    ''')

    conversations = cur.fetchall()
    cur.close()
    conn.close()

    conversation_list = []
    for conv in conversations:
        conversation_list.append({
            'user_id': conv[0],
            'user_name': conv[1],
            'username': conv[2],
            'last_message': conv[3],
            'last_message_time': conv[4].strftime('%Y-%m-%d %H:%M:%S') if conv[4] else '',
            'status': conv[5]
        })

    return jsonify({
        'success': True,
        'conversations': conversation_list
    })

@app.route('/api/admin/conversation/<int:user_id>')
def get_admin_conversation(user_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()

    # Get user info with block status
    cur.execute('''
        SELECT u.name, u.username, u.email,
               CASE 
                   WHEN EXISTS (SELECT 1 FROM user_blocks ub WHERE ub.user_id = u.id AND ub.blocked_until > CURRENT_TIMESTAMP) 
                   THEN 'blocked' 
                   ELSE 'active' 
               END as status
        FROM users u WHERE u.id = %s
    ''', (user_id,))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    # Get messages
    cur.execute('''
        SELECT content, sender_type, sender_name, created_at
        FROM conversations 
        WHERE user_id = %s 
        ORDER BY created_at ASC
    ''', (user_id,))

    messages = cur.fetchall()
    cur.close()
    conn.close()

    message_list = []
    for message in messages:
        message_list.append({
            'content': message[0],
            'sender_type': message[1],
            'sender_name': message[2],
            'created_at': message[3].strftime('%Y-%m-%d %H:%M:%S') if message[3] else ''
        })

    return jsonify({
        'success': True,
        'user': {
            'name': user[0],
            'username': user[1],
            'email': user[2],
            'status': user[3]
        },
        'messages': message_list
    })

@app.route('/api/admin/send-reply', methods=['POST'])
def send_admin_reply():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_id = data.get('user_id')
    content = data.get('content', '').strip()

    if not content or not user_id:
        return jsonify({'success': False, 'message': 'User ID and message content are required'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO conversations (user_id, content, sender_type, sender_name)
            VALUES (%s, %s, 'admin', 'Admin')
        ''', (user_id, content))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Reply sent successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to send reply'})

@app.route('/api/admin/block-user', methods=['POST'])
def block_user():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_id = data.get('user_id')
    duration_days = data.get('duration_days')

    if not user_id or not duration_days:
        return jsonify({'success': False, 'message': 'User ID and duration are required'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()

        # Remove any existing blocks for this user
        cur.execute('DELETE FROM user_blocks WHERE user_id = %s', (user_id,))

        # Add new block
        cur.execute('''
            INSERT INTO user_blocks (user_id, blocked_until)
            VALUES (%s, CURRENT_TIMESTAMP + INTERVAL '%s days')
        ''', (user_id, duration_days))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': f'User blocked for {duration_days} days'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to block user'})

@app.route('/api/admin/unblock-user', methods=['POST'])
def unblock_user():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'User ID is required'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()
        cur.execute('DELETE FROM user_blocks WHERE user_id = %s', (user_id,))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'User unblocked successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to unblock user'})

@app.route('/api/admin/clear-conversation', methods=['POST'])
def clear_conversation():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'User ID is required'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()
        cur.execute('DELETE FROM conversations WHERE user_id = %s', (user_id,))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Conversation cleared successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to clear conversation'})

@app.route('/api/admin/delete-conversation', methods=['DELETE'])
def delete_conversation():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'User ID is required'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()
        # Delete all messages for this user
        cur.execute('DELETE FROM conversations WHERE user_id = %s', (user_id,))
        # Also remove any blocks for this user
        cur.execute('DELETE FROM user_blocks WHERE user_id = %s', (user_id,))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Conversation deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to delete conversation'})

@app.route('/api/scan-performance', methods=['POST'])
def scan_performance():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'success': False, 'message': 'URL is required'})

    try:
        import requests
        import time

        # Multiple performance tests for better accuracy
        response_times = []
        status_codes = []

        # Perform multiple tests
        for i in range(3):
            try:
                start_time = time.time()
                response = requests.get(url, timeout=15, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                end_time = time.time()

                response_time = (end_time - start_time) * 1000  # in milliseconds
                response_times.append(response_time)
                status_codes.append(response.status_code)

                # Small delay between requests
                if i < 2:
                    time.sleep(0.5)

            except requests.exceptions.RequestException:
                response_times.append(10000)  # 10 second penalty for failed requests
                status_codes.append(0)

        # Calculate average response time
        avg_response_time = sum(response_times) / len(response_times)
        most_common_status = max(set(status_codes), key=status_codes.count)

        # Enhanced scoring algorithm
        if most_common_status == 200:
            # Base score calculation
            if avg_response_time < 100:
                base_score = 98
                grade = 'A+'
            elif avg_response_time < 200:
                base_score = 95
                grade = 'A+'
            elif avg_response_time < 300:
                base_score = 92
                grade = 'A'
            elif avg_response_time < 500:
                base_score = 88
                grade = 'A'
            elif avg_response_time < 800:
                base_score = 82
                grade = 'B+'
            elif avg_response_time < 1200:
                base_score = 76
                grade = 'B'
            elif avg_response_time < 1800:
                base_score = 68
                grade = 'C+'
            elif avg_response_time < 2500:
                base_score = 58
                grade = 'C'
            elif avg_response_time < 4000:
                base_score = 45
                grade = 'D'
            else:
                base_score = 25
                grade = 'F'

            # Consistency bonus/penalty
            consistency_variance = max(response_times) - min(response_times)
            if consistency_variance < 50:
                base_score += 2  # Bonus for consistency
            elif consistency_variance > 500:
                base_score -= 5  # Penalty for inconsistency

            # Ensure score doesn't exceed 100
            score = min(100, max(0, base_score))

        elif most_common_status in [301, 302, 307, 308]:
            score = 75  # Redirect penalty
            grade = 'B'
        elif most_common_status in [404, 403, 500, 502, 503]:
            score = 0
            grade = 'F'
        else:
            score = 30
            grade = 'D'

        # Try alternative performance API for cross-validation
        try:
            # Using Google PageSpeed Insights API (free tier)
            pagespeed_url = f"https://www.googleapis.com/pagespeed/v5/runPagespeed?url={url}&strategy=desktop"
            pagespeed_response = requests.get(pagespeed_url, timeout=10)

            if pagespeed_response.status_code == 200:
                pagespeed_data = pagespeed_response.json()
                if 'lighthouseResult' in pagespeed_data:
                    lighthouse_score = pagespeed_data['lighthouseResult']['categories']['performance']['score']
                    if lighthouse_score:
                        lighthouse_score = int(lighthouse_score * 100)
                        # Average with our score for better accuracy
                        score = int((score + lighthouse_score) / 2)

                        # Update grade based on final score
                        if score >= 98:
                            grade = 'A+'
                        elif score >= 90:
                            grade = 'A'
                        elif score >= 80:
                            grade = 'B+'
                        elif score >= 70:
                            grade = 'B'
                        elif score >= 60:
                            grade = 'C+'
                        elif score >= 50:
                            grade = 'C'
                        elif score >= 40:
                            grade = 'D'
                        else:
                            grade = 'F'
        except:
            pass  # Fall back to our original score if PageSpeed fails

        return jsonify({
            'success': True,
            'performance': {
                'score': score,
                'grade': grade,
                'response_time': round(avg_response_time, 2),
                'status_code': most_common_status,
                'tests_performed': len(response_times)
            }
        })

    except requests.exceptions.RequestException as e:
        return jsonify({
            'success': False,
            'message': 'Failed to reach the URL'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Error occurred during scanning'
        })

@app.route('/users-chat')
def users_chat():
    if not session.get('user_id'):
        return redirect('/auth')
    return render_template('users_chat.html')

@app.route('/developers')
def developers():
    return render_template('developers.html')

@app.route('/users')
def admin_users():
    if not session.get('admin'):
        return redirect(url_for('index'))
    return render_template('users.html')

@app.route('/api/approved-users')
def get_approved_users():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    current_user_id = session.get('user_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()
    cur.execute('''
        SELECT id, name, username FROM users 
        WHERE status = 'approved' AND id != %s
        ORDER BY name
    ''', (current_user_id,))

    users = cur.fetchall()
    cur.close()
    conn.close()

    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'name': user[1],
            'username': user[2]
        })

    return jsonify({
        'success': True,
        'users': user_list
    })

@app.route('/api/user-conversation/<int:user_id>')
def get_user_to_user_conversation(user_id):
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    current_user_id = session.get('user_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()

    # Get other user info
    cur.execute('SELECT name, username FROM users WHERE id = %s', (user_id,))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    # Get messages between users
    cur.execute('''
        SELECT uc.content, uc.sender_id, uc.created_at, u.name, u.username
        FROM user_conversations uc
        JOIN users u ON uc.sender_id = u.id
        WHERE (uc.sender_id = %s AND uc.receiver_id = %s) 
           OR (uc.sender_id = %s AND uc.receiver_id = %s)
        ORDER BY uc.created_at ASC
    ''', (current_user_id, user_id, user_id, current_user_id))

    messages = cur.fetchall()
    cur.close()
    conn.close()

    message_list = []
    for message in messages:
        message_list.append({
            'content': message[0],
            'sender_id': message[1],
            'is_own': message[1] == current_user_id,
            'created_at': message[2].strftime('%Y-%m-%d %H:%M:%S') if message[2] else '',
            'sender_name': message[3],
            'sender_username': message[4]
        })

    return jsonify({
        'success': True,
        'user': {
            'name': user[0],
            'username': user[1]
        },
        'messages': message_list
    })

@app.route('/api/send-user-message', methods=['POST'])
def send_user_message():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    sender_id = session.get('user_id')
    data = request.json
    receiver_id = data.get('receiver_id')
    content = data.get('content', '').strip()

    if not content or not receiver_id:
        return jsonify({'success': False, 'message': 'Receiver ID and message content are required'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO user_conversations (sender_id, receiver_id, content)
            VALUES (%s, %s, %s)
        ''', (sender_id, receiver_id, content))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Message sent successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to send message'})

@app.route('/api/admin/user-conversations')
def get_admin_user_conversations():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()
    cur.execute('''
        SELECT DISTINCT 
            LEAST(uc.sender_id, uc.receiver_id) as user1_id,
            GREATEST(uc.sender_id, uc.receiver_id) as user2_id,
            u1.name as user1_name,
            u1.username as user1_username,
            u2.name as user2_name,
            u2.username as user2_username,
            (SELECT content FROM user_conversations uc2 
             WHERE (uc2.sender_id = LEAST(uc.sender_id, uc.receiver_id) AND uc2.receiver_id = GREATEST(uc.sender_id, uc.receiver_id))
                OR (uc2.sender_id = GREATEST(uc.sender_id, uc.receiver_id) AND uc2.receiver_id = LEAST(uc.sender_id, uc.receiver_id))
             ORDER BY uc2.created_at DESC LIMIT 1) as last_message,
            (SELECT created_at FROM user_conversations uc2 
             WHERE (uc2.sender_id = LEAST(uc.sender_id, uc.receiver_id) AND uc2.receiver_id = GREATEST(uc.sender_id, uc.receiver_id))
                OR (uc2.sender_id = GREATEST(uc.sender_id, uc.receiver_id) AND uc2.receiver_id = LEAST(uc.sender_id, uc.receiver_id))
             ORDER BY uc2.created_at DESC LIMIT 1) as last_message_time
        FROM user_conversations uc
        JOIN users u1 ON LEAST(uc.sender_id, uc.receiver_id) = u1.id
        JOIN users u2 ON GREATEST(uc.sender_id, uc.receiver_id) = u2.id
        ORDER BY last_message_time DESC
    ''')

    conversations = cur.fetchall()
    cur.close()
    conn.close()

    conversation_list = []
    for conv in conversations:
        conversation_list.append({
            'user1_id': conv[0],
            'user2_id': conv[1],
            'user1_name': conv[2],
            'user1_username': conv[3],
            'user2_name': conv[4],
            'user2_username': conv[5],
            'last_message': conv[6],
            'last_message_time': conv[7].strftime('%Y-%m-%d %H:%M:%S') if conv[7] else ''
        })

    return jsonify({
        'success': True,
        'conversations': conversation_list
    })

@app.route('/api/admin/user-conversation/<int:user1_id>/<int:user2_id>')
def get_admin_user_conversation(user1_id, user2_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()

    # Get user info
    cur.execute('SELECT name, username FROM users WHERE id = %s', (user1_id,))
    user1 = cur.fetchone()
    cur.execute('SELECT name, username FROM users WHERE id = %s', (user2_id,))
    user2 = cur.fetchone()

    if not user1 or not user2:
        cur.close()
        conn.close()
        return jsonify({'error': 'Users not found'}), 404

    # Get messages between users
    cur.execute('''
        SELECT uc.content, uc.sender_id, uc.created_at, u.name, u.username
        FROM user_conversations uc
        JOIN users u ON uc.sender_id = u.id
        WHERE (uc.sender_id = %s AND uc.receiver_id = %s) 
           OR (uc.sender_id = %s AND uc.receiver_id = %s)
        ORDER BY uc.created_at ASC
    ''', (user1_id, user2_id, user2_id, user1_id))

    messages = cur.fetchall()
    cur.close()
    conn.close()

    message_list = []
    for message in messages:
        message_list.append({
            'content': message[0],
            'sender_id': message[1],
            'created_at': message[2].strftime('%Y-%m-%d %H:%M:%S') if message[2] else '',
            'sender_name': message[3],
            'sender_username': message[4]
        })

    return jsonify({
        'success': True,
        'user1': {
            'id': user1_id,
            'name': user1[0],
            'username': user1[1]
        },
        'user2': {
            'id': user2_id,
            'name': user2[0],
            'username': user2[1]
        },
        'messages': message_list
    })

@app.route('/api/admin/clear-user-conversation', methods=['POST'])
def clear_user_conversation():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user1_id = data.get('user1_id')
    user2_id = data.get('user2_id')

    if not user1_id or not user2_id:
        return jsonify({'success': False, 'message': 'Both user IDs are required'})

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()
        cur.execute('''
            DELETE FROM user_conversations 
            WHERE (sender_id = %s AND receiver_id = %s) 
               OR (sender_id = %s AND receiver_id = %s)
        ''', (user1_id, user2_id, user2_id, user1_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Conversation cleared successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to clear conversation'})

@app.route('/premium-users')
def premium_users():
    if not session.get('admin'):
        return redirect(url_for('index'))
    return render_template('premium_users.html')

@app.route('/premium-tools')
def premium_tools():
    if not session.get('user_id'):
        return redirect(url_for('index'))
    
    # Check if user has approved premium status
    user_id = session.get('user_id')
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('index'))
    
    cur = conn.cursor()
    cur.execute('SELECT premium_status FROM premium_applications WHERE user_id = %s', (user_id,))
    premium_app = cur.fetchone()
    cur.close()
    conn.close()
    
    if not premium_app or premium_app[0] != 'approved':
        return redirect(url_for('dashboard'))
    
    return render_template('premium_tools.html')

@app.route('/api/apply-premium', methods=['POST'])
def apply_premium():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session.get('user_id')
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'})

    try:
        cur = conn.cursor()
        
        # Check if user already applied
        cur.execute('SELECT premium_status FROM premium_applications WHERE user_id = %s', (user_id,))
        existing = cur.fetchone()
        
        if existing:
            if existing[0] == 'pending':
                return jsonify({'success': False, 'message': 'Application already pending'})
            elif existing[0] == 'approved':
                return jsonify({'success': False, 'message': 'Already approved for premium'})
            else:  # rejected - allow reapplication
                cur.execute('''
                    UPDATE premium_applications 
                    SET premium_status = 'pending', premium_applied_at = CURRENT_TIMESTAMP 
                    WHERE user_id = %s
                ''', (user_id,))
        else:
            cur.execute('''
                INSERT INTO premium_applications (user_id, premium_status)
                VALUES (%s, 'pending')
            ''', (user_id,))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Premium application submitted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to submit application'})

@app.route('/api/check-premium-status')
def check_premium_status():
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session.get('user_id')
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()
    cur.execute('SELECT premium_status FROM premium_applications WHERE user_id = %s ORDER BY premium_applied_at DESC LIMIT 1', (user_id,))
    premium_app = cur.fetchone()
    cur.close()
    conn.close()

    if premium_app:
        status = premium_app[0]
        return jsonify({
            'has_applied': True,
            'status': status,
            'is_premium': status == 'approved'
        })
    else:
        return jsonify({
            'has_applied': False,
            'status': None,
            'is_premium': False
        })

@app.route('/api/premium-users/all')
def get_premium_users():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    cur = conn.cursor()
    cur.execute('''
        SELECT u.id, u.name, u.username, u.email, u.status,
               pa.premium_status, pa.premium_applied_at, pa.premium_approved_at
        FROM users u
        JOIN premium_applications pa ON u.id = pa.user_id
        ORDER BY pa.premium_applied_at DESC
    ''')

    users = cur.fetchall()
    cur.close()
    conn.close()

    user_list = []
    for user in users:
        user_list.append({
            'id': user[0],
            'name': user[1],
            'username': user[2],
            'email': user[3],
            'status': user[4],
            'premium_status': user[5],
            'premium_applied_at': user[6].strftime('%Y-%m-%d %H:%M:%S') if user[6] else '',
            'premium_approved_at': user[7].strftime('%Y-%m-%d %H:%M:%S') if user[7] else ''
        })

    return jsonify(user_list)

@app.route('/api/premium-users/<int:user_id>/status', methods=['PUT'])
def update_premium_status(user_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    status = data.get('status')

    if status not in ['approved', 'rejected', 'pending']:
        return jsonify({'error': 'Invalid status'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection error'}), 500

    try:
        cur = conn.cursor()
        
        if status == 'approved':
            cur.execute('''
                UPDATE premium_applications 
                SET premium_status = %s, premium_approved_at = CURRENT_TIMESTAMP 
                WHERE user_id = %s
            ''', (status, user_id))
        else:
            cur.execute('''
                UPDATE premium_applications 
                SET premium_status = %s, premium_approved_at = NULL 
                WHERE user_id = %s
            ''', (status, user_id))
        
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True, 'message': f'Premium status updated to {status}'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to update premium status'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)