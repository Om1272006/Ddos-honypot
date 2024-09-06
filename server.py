import time
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import logging
import signal
from functools import partial
import re
import hashlib
import json
import ipaddress

# Blockchain implementation for logging
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(previous_hash='1')  # Genesis block

    def create_block(self, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'previous_hash': previous_hash or self.hash(self.chain[-1]) if self.chain else '1'
        }
        self.chain.append(block)
        return block

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def add_log(self, action, ip_address, additional_info=None):
        block = self.create_block()
        block['action'] = action
        block['ip_address'] = ip_address
        if additional_info:
            block['additional_info'] = additional_info
        logging.info(f"Log added to blockchain: {block}")

# Extended list of malicious keywords or patterns to check for in requests
MALICIOUS_PATTERNS = [
    # Add patterns here (as defined in your original code)
    # Example patterns
    r"<script.?>.?</script>",
    r"javascript:.*",
    r"on\w+=",
    r"alert\(.*\)",
    r"eval\(.*\)",
    r"document\.cookie",
    r"document\.location",
    r"window\.location",
    r"iframe.?src=.?http",
    r"data:text/html;base64,",
    r"union\s+select",
    r"select\s+.*\s+from\s+information_schema.tables",
    r"select\s+.*\s+from\s+mysql.db",
    r"or\s+1=1",
    r"and\s+1=1",
    r"drop\s+table",
    r"insert\s+into\s+.\s+values\s+\(.\)",
    r"update\s+.\s+set\s+.\s+where\s+.*",
    r"delete\s+from\s+.\s+where\s+.",
    r"load_file\(",
    r"outfile\s+.*",
    r"exec\s+sp_executesql",
    r"sp_password",
    r"cmd\.exe\s+/c",
    r"powershell\s+[-]c",
    r"bash\s+-c",
    r"nc\s+-e",
    r"wget\s+http",
    r"curl\s+http",
    r"php\s+shell_exec",
    r"php\s+system",
    r"php\s+passthru",
    r"perl\s+-e",
    r"python\s+-c",
    r"exec\(.*\)",
    r"system\(.*\)",
    r"shell_exec\(.*\)",
    r"sh\s+-c",
    r"\.\./",
    r"\.\./\.\./",
    r"php\s+include",
    r"php\s+require",
    r"include\s+.*",
    r"require\s+.*",
    r"file_get_contents\(.*\)",
    r"fopen\(.*\)",
    r"eval\(.*\)",
    r"assert\(.*\)",
    r"preg_replace\(.*\)",
    r"ransomware",
    r"backdoor",
    r"remote\s+shell",
    r"reverse\s+shell",
    r"bind\s+shell",
    r"base64_decode",
    r"phpinfo\(\)",
    r"mysql_query\(.*\)",
    r"mysqli_query\(.*\)",
    r"pdo_query\(.*\)",
    r"base64_encode",
    r"remote\s+file\s+inclusion",
    r"local\s+file\s+inclusion",
    r"ftp://",
    r"file://",
    r"http[s]?://\S+\.(exe|sh|bat|pl|py)",
    r"cmd.exe\s+/c\s+start\s+http",
    r"telnet\s+\d+\.\d+\.\d+\.\d+",
]

def contains_malicious_content(data):
    """Check if the request data contains any malicious patterns."""
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            return True
    return False

class RequestMonitor:
    def __init__(self, threshold=20, time_window=60, redirect_url=None, blockchain=None):
        self.request_count = defaultdict(int)
        self.request_times = defaultdict(list)
        self.blocked_ips = set()
        self.network_blocks = defaultdict(set)
        self.threshold = threshold
        self.time_window = time_window
        self.redirect_url = redirect_url
        self.blockchain = blockchain
        self.lock = threading.Lock()

    def add_request(self, client_address):
        current_time = time.time()
        client_ip = client_address[0]
        client_network = self.get_network(client_ip)

        with self.lock:
            if client_ip in self.blocked_ips:
                return False

            # Handle requests from the same network
            if client_network in self.network_blocks and len(self.network_blocks[client_network]) > self.threshold:
                self.block_ip(client_ip, client_network)
                return False

            self.request_times[client_ip].append(current_time)
            self.request_count[client_ip] += 1

            while self.request_times[client_ip] and self.request_times[client_ip][0] < current_time - self.time_window:
                self.request_times[client_ip].pop(0)
                self.request_count[client_ip] -= 1

            if self.request_count[client_ip] > self.threshold:
                logging.warning(f"High request volume from {client_ip}. Count: {self.request_count[client_ip]}")
                if self.redirect_url:
                    if self.blockchain:
                        self.blockchain.add_log('Redirect', client_ip)
                    return self.redirect_url
                else:
                    self.block_ip(client_ip, client_network)
                    return False

            return True

    def get_network(self, ip):
        """Determine the network address for a given IP."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Define private network ranges (CIDR notation)
            private_networks = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16')
            ]
            for network in private_networks:
                if ip_obj in network:
                    return str(network)
            return None
        except ValueError:
            return None

    def block_ip(self, client_ip, client_network=None):
        with self.lock:
            self.blocked_ips.add(client_ip)
            if client_network:
                self.network_blocks[client_network].add(client_ip)
            logging.info(f"Blocked IP address: {client_ip}")
            if self.blockchain:
                self.blockchain.add_log('Block', client_ip)

class MonitoringHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, request_monitor=None, **kwargs):
        self.request_monitor = request_monitor
        super().__init__(*args, **kwargs)

    def do_GET(self):
        redirect_url = self.request_monitor.add_request(self.client_address[0])
        if redirect_url is False:
            self.send_error(403, "Your IP has been blocked due to high request volume.")
            return
        elif isinstance(redirect_url, str):
            self.send_response(302)  # Redirect response
            self.send_header('Location', redirect_url)
            self.end_headers()
            return

        if self.path == "/" or self.path == "/index.html":
            self.serve_content(self.get_html_content(), "text/html")
        elif self.path == "/stylesheet.css":
            self.serve_content(self.get_css_content(), "text/css")
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        redirect_url = self.request_monitor.add_request(self.client_address[0])
        if redirect_url is False:
            self.send_error(403, "Your IP has been blocked due to high request volume.")
            return
        elif isinstance(redirect_url, str):
            self.send_response(302)  # Redirect response
            self.send_header('Location', redirect_url)
            self.end_headers()
            return

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        if contains_malicious_content(post_data):
            self.request_monitor.block_ip(self.client_address[0])
            self.send_error(403, "Malicious content detected. Your IP has been blocked.")
            if self.blockchain:
                self.blockchain.add_log('Malicious content detected', self.client_address[0], additional_info=post_data)
            return

        self.send_response(200)
        self.end_headers()

    def serve_content(self, content, content_type):
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def get_html_content(self):
        """Returns HTML content as a string."""
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SecureNet Firewall - Protect Your Digital World</title>
            <link rel="stylesheet" href="/stylesheet.css">
        </head>
        <body>
            <!-- Header Section -->
            <header>
                <div class="container">
                    <h1>SecureNet Firewall</h1>
                    <p>Protect Your Digital World with Advanced Security Solutions</p>
                    <a href="#learn-more" class="cta-button">Learn More</a>
                </div>
            </header>

            <!-- Main Content Section -->
            <main>
                <!-- Features Section -->
                <section id="features">
                    <h2>Key Features</h2>
                    <div class="feature-list">
                        <div class="feature-item">
                            <h3>Advanced Threat Protection</h3>
                            <p>Detect and block malicious attacks before they reach your network.</p>
                        </div>
                        <div class="feature-item">
                            <h3>Real-Time Monitoring</h3>
                            <p>Stay updated with real-time alerts and comprehensive reporting tools.</p>
                        </div>
                        <div class="feature-item">
                            <h3>Seamless Integration</h3>
                            <p>Integrates easily with your existing infrastructure with minimal setup.</p>
                        </div>
                        <div class="feature-item">
                            <h3>User-Friendly Interface</h3>
                            <p>Simple and intuitive dashboard for effortless management and configuration.</p>
                        </div>
                    </div>
                </section>

                <!-- Benefits Section -->
                <section id="benefits">
                    <h2>Why Choose SecureNet Firewall?</h2>
                    <ul>
                        <li>Reduce risks and protect your data from cyber threats.</li>
                        <li>Ensure business continuity with robust security measures.</li>
                        <li>Comply with industry standards and regulations effortlessly.</li>
                        <li>24/7 support from our experienced security experts.</li>
                    </ul>
                </section>

                <!-- Call to Action Section -->
                <section id="cta">
                    <h2>Get Started Today</h2>
                    <p>Contact us now to learn more about how SecureNet Firewall can safeguard your organization.</p>
                    <a href="#contact" class="cta-button">Contact Us</a>
                </section>
            </main>

            <!-- Footer Section -->
            <footer>
                <p>&copy; 2024 SecureNet. All rights reserved.</p>
            </footer>
        </body>
        </html>
        """

    def get_css_content(self):
        """Returns CSS content as a string."""
        return """
        /* General Styles */
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
            color: #333;
        }

        header {
            background: linear-gradient(to right, #0052cc, #66ccff);
            color: #fff;
            text-align: center;
            padding: 50px 0;
        }

        header .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header h1 {
            font-size: 3em;
            margin: 0;
        }

        header p {
            font-size: 1.5em;
            margin: 10px 0;
        }

        .cta-button {
            background-color: #ff6600;
            color: #fff;
            padding: 15px 30px;
            text-decoration: none;
            font-weight: bold;
            border-radius: 5px;
            display: inline-block;
            margin-top: 20px;
        }

        .cta-button:hover {
            background-color: #ff4500;
        }

        main {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        #features, #benefits, #cta {
            margin: 40px 0;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        .feature-list {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }

        .feature-item {
            flex: 1 1 calc(50% - 20px);
            background-color: #e6f7ff;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        """

def run_server(server_class=HTTPServer, handler_class=MonitoringHandler, port=8000):
    blockchain = Blockchain()  # Initialize blockchain for logging
    request_monitor = RequestMonitor(
        threshold=20, 
        time_window=60, 
        redirect_url="https://www.example.com", 
        blockchain=blockchain
    )
    handler = partial(handler_class, request_monitor=request_monitor)

    httpd = server_class(('localhost', port), handler)
    logging.info(f"Starting server on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # Allow keyboard interrupt to stop server
    run_server()
