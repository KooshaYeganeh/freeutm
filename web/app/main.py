#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import subprocess
import os
import sys
import logging
import datetime
import glob
import shutil
import config
import psutil
import platform
import socket
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Setup logging
logging.basicConfig(
    filename='/tmp/kygnus_utm.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = {1: User(1)}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# Utility Functions
def run_command(cmd, sudo=False):
    try:
        if sudo:
            cmd = f"sudo {cmd}"
        result = subprocess.run(
            cmd, 
            shell=True, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}\nError: {e.stderr}")
        return False, e.stderr

def sudo_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not os.geteuid() == 0:
            flash("This action requires root privileges", "danger")
            return redirect(request.referrer or url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_hostname():
    return socket.gethostname()

def get_uptime():
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
        return str(datetime.timedelta(seconds=uptime_seconds))

def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def get_memory_usage():
    mem = psutil.virtual_memory()
    return {
        'total': mem.total,
        'available': mem.available,
        'percent': mem.percent,
        'used': mem.used,
        'free': mem.free
    }

def get_service_status(service_name):
    try:
        status = subprocess.run(
            f"systemctl is-active {service_name}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return status.stdout.strip()
    except:
        return "inactive"

def get_selinux_status():
    try:
        status = subprocess.run(
            "getenforce",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return status.stdout.strip().lower()
    except:
        return "disabled"

def get_current_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_installed_tools():
    tools = {
        'snort': os.path.exists('/usr/sbin/snort'),
        'suricata': os.path.exists('/usr/bin/suricata'),
        'zeek': os.path.exists('/usr/bin/zeek'),
        'clamav': os.path.exists('/usr/bin/clamscan'),
        'maldet': os.path.exists('/usr/local/maldetect/maldet'),
        'rkhunter': os.path.exists('/usr/bin/rkhunter'),
        'yara': os.path.exists('/usr/bin/yara')
    }
    return tools

# Routes
@app.route('/')
@login_required
def index():
    # Get all system information
    system_info = {
        'hostname': get_hostname(),
        'uptime': get_uptime(),
        'os': platform.system(),
        'os_version': platform.version(),
        'cpu_usage': get_cpu_usage(),
        'memory': get_memory_usage(),
        'last_updated': get_current_time()
    }
    
    # Get service statuses
    firewalld = get_service_status('firewalld')
    clamstatus = get_service_status('clamav-daemon') or get_service_status('clamav')
    fail2ban_status = get_service_status('fail2ban')
    sestatus = get_selinux_status()
    network_status = get_service_status('NetworkManager')
    samba_status = get_service_status('smbd')
    nfs_status = get_service_status('nfs-server')
    
    # Check IDS status (try multiple services)
    ids_status = "inactive"
    for service in ['snort', 'suricata', 'zeek']:
        if get_service_status(service) == "active":
            ids_status = "active"
            break
    
    # Get installed tools status
    tools_status = get_installed_tools()
    
    return render_template(
        'index.html',
        system_info=system_info,
        username=config.ADMIN_USER,
        now_time=get_current_time(),
        firewalld=firewalld,
        clamstatus=clamstatus,
        fail2ban_status=fail2ban_status,
        sestatus=sestatus,
        network_status=network_status,
        samba_status=samba_status,
        nfs_status=nfs_status,
        ids_status=ids_status,
        tools_status=tools_status,
        services_status="active"  # Default value
    )

@app.route('/home')
@login_required
def home():
    return index()


@app.route('/firewall/add_rule')
def firewall_add_rule_get():
    return render_template("add_rule.html")

# Firewall Management Routes
@app.route('/firewall/add_rule', methods=['GET', 'POST'])
@login_required
@sudo_required
def firewall_add_rule():
    if request.method == 'POST':
        rule = request.form.get('rule')
        chain = request.form.get('chain', 'INPUT')
        success, output = run_command(f"iptables -A {chain} {rule}", sudo=True)
        if success:
            flash(f"Rule added to {chain}: {rule}", "success")
        else:
            flash(f"Failed to add rule: {output}", "danger")
        return redirect(url_for('firewall_add_rule'))
    
    return render_template('add_rule.html')



@app.route('/firewall/remove_rule')
def firewall_remove_rule_get():
    return render_template("remove_rule.html")

@app.route('/firewall/remove_rule', methods=['GET', 'POST'])
@login_required
@sudo_required
def firewall_remove_rule():
    if request.method == 'POST':
        chain = request.form.get('chain', 'INPUT')
        rule_num = request.form.get('rule_num')
        success, output = run_command(f"iptables -D {chain} {rule_num}", sudo=True)
        if success:
            flash(f"Rule {rule_num} removed from {chain}", "success")
        else:
            flash(f"Failed to remove rule: {output}", "danger")
        return redirect(url_for('firewall_remove_rule'))
    
    # Get current rules
    success, rules = run_command("iptables -L -n --line-numbers", sudo=True)
    return render_template('remove_rule.html', rules=rules if success else None)


@app.route('/firewall/list_rules')
def firewall_list_rules_get():
    return render_template("list_rule.html")

@app.route('/firewall/list')
@login_required
def firewall_list():
    success, rules = run_command("iptables -L -n -v --line-numbers", sudo=True)
    return render_template('list_rules.html', rules=rules if success else None)

# IDS/IPS Routes
@app.route('/ids/snort', methods=['GET', 'POST'])
@login_required
@sudo_required
def ids_snort():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_rule':
            rule = request.form.get('rule')
            with open("/etc/snort/rules/local.rules", "a") as f:
                f.write(f"{rule}\n")
            flash("Snort rule added", "success")
        elif action in ['start', 'stop', 'restart']:
            success, output = run_command(f"systemctl {action} snort", sudo=True)
            if success:
                flash(f"Snort {action}ed successfully", "success")
            else:
                flash(f"Failed to {action} Snort: {output}", "danger")
        return redirect(url_for('ids_snort'))
    
    # Get snort status and rules
    status = get_service_status('snort')
    rules = []
    if os.path.exists("/etc/snort/rules/local.rules"):
        with open("/etc/snort/rules/local.rules", "r") as f:
            rules = f.readlines()
    
    return render_template('ids/snort.html', status=status, rules=rules)

@app.route('/ids/suricata', methods=['GET', 'POST'])
@login_required
@sudo_required
def ids_suricata():
    if request.method == 'POST':
        action = request.form.get('action')
        if action in ['start', 'stop', 'restart']:
            success, output = run_command(f"systemctl {action} suricata", sudo=True)
            if success:
                flash(f"Suricata {action}ed successfully", "success")
            else:
                flash(f"Failed to {action} Suricata: {output}", "danger")
        return redirect(url_for('ids_suricata'))
    
    status = get_service_status('suricata')
    return render_template('ids/suricata.html', status=status)

# Antivirus Routes



@app.route('/av/clamav')
@login_required
def av_clamav_get():
    return render_template("av.html")


@app.route('/av/clamav', methods=['POST'])
@login_required
@sudo_required
def av_clamav():
    if request.method == 'POST':
        path = request.form.get('path', '/')
        success, output = run_command(f"clamscan -r --bell {path}", sudo=True)
        if success:
            flash(f"ClamAV scan completed for {path}", "success")
        else:
            flash(f"Scan failed: {output}", "danger")
        return redirect(url_for('av_clamav'))
    
    status = get_service_status('clamav-daemon') or get_service_status('clamav')
    return render_template('av.html', status=status)

@app.route('/av/maldet', methods=['GET', 'POST'])
@login_required
@sudo_required
def av_maldet():
    if request.method == 'POST':
        path = request.form.get('path', '/')
        success, output = run_command(f"/usr/local/sbin/maldet -a {path}", sudo=True)
        if success:
            flash(f"Maldet scan completed for {path}", "success")
        else:
            flash(f"Scan failed: {output}", "danger")
        return redirect(url_for('av_maldet'))
    
    return render_template('av.html')

@app.route('/av/rootkit', methods=['GET', 'POST'])
@login_required
@sudo_required
def rkhunter():
    if request.method == 'POST':
        path = request.form.get('path', '/')
        success, output = run_command(f"rkhunter --check --skip-keypress", sudo=True)
        if success:
            flash(f"rkhunter scan completed for {path}", "success")
        else:
            flash(f"Scan failed: {output}", "danger")
        return redirect(url_for('rkhunter'))
    
    return render_template('av.html')



@app.route('/av/chrootkit', methods=['GET', 'POST'])
@login_required
@sudo_required
def chkrootkit():
    if request.method == 'POST':
        path = request.form.get('path', '/')
        success, output = run_command(f"chkrootkit", sudo=True)
        if success:
            flash(f"chkrootkit scan completed for {path}", "success")
        else:
            flash(f"Scan failed: {output}", "danger")
        return redirect(url_for('chkrootkit'))
    
    return render_template('av.html')





@app.route('/av/yara', methods=['GET', 'POST'])
@login_required
@sudo_required
def yara():
    if request.method == 'POST':
        path = request.form.get('path', '/')
        success, output = run_command(f"chkrootkit", sudo=True)
        if success:
            flash(f"chkrootkit scan completed for {path}", "success")
        else:
            flash(f"Scan failed: {output}", "danger")
        return redirect(url_for('chkrootkit'))
    
    return render_template('av.html')




# Services Routes
@app.route('/services/list')
@login_required
def services_list():
    success, output = run_command("systemctl list-units --type=service --no-pager", sudo=True)
    services = output.split('\n') if success else []
    return render_template('services/list.html', services=services)

@app.route('/services/start')
@login_required
@sudo_required
def services_start():
    success, output = run_command("systemctl list-unit-files --state=enabled --no-pager", sudo=True)
    services = output.split('\n') if success else []
    return render_template('services/start.html', services=services)

# Kernel Routes
@app.route('/kernel/parameters', methods=['GET', 'POST'])
@login_required
@sudo_required
def kernel_parameters():
    if request.method == 'POST':
        param = request.form.get('param')
        value = request.form.get('value')
        success, output = run_command(f"sysctl -w {param}={value}", sudo=True)
        if success:
            flash(f"Parameter set: {param}={value}", "success")
        else:
            flash(f"Failed to set parameter: {output}", "danger")
        return redirect(url_for('kernel_parameters'))
    
    success, output = run_command("sysctl -a", sudo=True)
    params = output.split('\n') if success else []
    return render_template('kernel/parameters.html', params=params)

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == config.ADMIN_USER and password == config.ADMIN_PASS:
            user = User(1)
            login_user(user)
            flash("Logged in successfully", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials", "danger")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

# Info Route
@app.route('/info')
@login_required
def info():
    system_info = {
        'hostname': get_hostname(),
        'uptime': get_uptime(),
        'os': platform.system(),
        'os_version': platform.version(),
        'cpu_usage': get_cpu_usage(),
        'memory': get_memory_usage(),
        'last_updated': get_current_time()
    }
    return render_template('info.html', system_info=system_info)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=True)