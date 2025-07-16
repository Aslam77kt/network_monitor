import psutil
import time
import speedtest
from scapy.all import sniff, IP
from flask import Flask, render_template, jsonify, request
import threading
import queue
import logging
from datetime import datetime
import socket
import subprocess
import platform

app = Flask(__name__)

# Set up logging
logging.basicConfig(filename='network_monitor.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables for monitoring
packet_count = 0
bandwidth_data = {'sent': 0, 'recv': 0}
latency_data = []
speed_test_data = {'download': 0, 'upload': 0}
performance_data = {'jitter': 0, 'packet_loss': 0}
start_time = time.time()
q = queue.Queue()

def get_network_interfaces():
    """Get available network interfaces."""
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def monitor_bandwidth(interface='eth0', interval=1):
    """Monitor network bandwidth usage."""
    global bandwidth_data
    while True:
        try:
            net_io = psutil.net_io_counters(pernic=True)
            if interface in net_io:
                initial = net_io[interface]
                time.sleep(interval)
                final = net_io[interface]
                
                sent_bps = (final.bytes_sent - initial.bytes_sent) / interval
                recv_bps = (final.bytes_recv - initial.bytes_recv) / interval
                
                bandwidth_data = {
                    'sent': sent_bps / 1024 / 1024,  # Convert to MB/s
                    'recv': recv_bps / 1024 / 1024,  # Convert to MB/s
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }
                
                q.put({'bandwidth': bandwidth_data})
                logging.info(f"Bandwidth - Sent: {bandwidth_data['sent']:.2f} MB/s, "
                           f"Recv: {bandwidth_data['recv']:.2f} MB/s")
        except Exception as e:
            logging.error(f"Bandwidth monitoring error: {str(e)}")
        time.sleep(interval)

def packet_callback(packet):
    """Callback function for packet sniffing."""
    global packet_count
    if IP in packet:
        packet_count += 1
        q.put({'packet_count': packet_count})

def sniff_packets(interface='eth0'):
    """Sniff network packets."""
    try:
        sniff(iface=interface, prn=packet_callback, store=0, count=0)
    except Exception as e:
        logging.error(f"Packet sniffing error: {str(e)}")

def measure_latency(host="8.8.8.8"):
    """Measure latency to a host using socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        start = time.time()
        sock.connect((host, 80))
        latency = (time.time() - start) * 1000  # Convert to ms
        sock.close()
        
        latency_data.append({
            'latency': latency,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })
        if len(latency_data) > 50:
            latency_data.pop(0)
            
        q.put({'latency': latency})
        logging.info(f"Latency to {host}: {latency:.2f} ms")
        return latency
    except Exception as e:
        logging.error(f"Latency measurement error: {str(e)}")
        return None

def ping_host(host="8.8.8.8"):
    """Ping a host using system ping command."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', host]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        q.put({'ping': output})
        logging.info(f"Ping to {host}: {output}")
        return output
    except subprocess.CalledProcessError as e:
        logging.error(f"Ping error: {str(e)}")
        return None

def measure_performance(host="8.8.8.8", count=5):
    """Measure network performance (jitter and packet loss)."""
    global performance_data
    latencies = []
    packets_sent = count
    packets_received = 0
    
    for _ in range(count):
        latency = measure_latency(host)
        if latency is not None:
            latencies.append(latency)
            packets_received += 1
        time.sleep(1)
    
    if len(latencies) > 1:
        jitter = sum(abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))) / (len(latencies) - 1)
        packet_loss = ((packets_sent - packets_received) / packets_sent) * 100
        performance_data = {
            'jitter': jitter,
            'packet_loss': packet_loss,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        q.put({'performance': performance_data})
        logging.info(f"Performance - Jitter: {jitter:.2f} ms, Packet Loss: {packet_loss:.2f}%")

def run_speed_test():
    """Run internet speed test."""
    global speed_test_data
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        
        speed_test_data = {
            'download': download_speed,
            'upload': upload_speed,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        q.put({'speed_test': speed_test_data})
        logging.info(f"Speed Test - Download: {download_speed:.2f} Mbps, Upload: {upload_speed:.2f} Mbps")
    except Exception as e:
        logging.error(f"Speed test error: {str(e)}")

@app.route('/')
def index():
    """Render the main dashboard."""
    interfaces = get_network_interfaces()
    return render_template('index.html', interfaces=interfaces)

@app.route('/data/<tool>')
def get_data(tool):
    """Return real-time data for the selected tool."""
    if tool == 'network_monitor':
        data = {
            'bandwidth': bandwidth_data,
            'packet_count': packet_count,
            'latency': latency_data[-10:] if latency_data else []
        }
    elif tool == 'performance_tester':
        data = {
            'performance': performance_data
        }
    elif tool == 'speed_test':
        data = {
            'speed_test': speed_test_data
        }
    else:
        data = {
            'bandwidth': bandwidth_data,
            'packet_count': packet_count,
            'latency': latency_data[-10:] if latency_data else [],
            'performance': performance_data,
            'speed_test': speed_test_data
        }
    return jsonify(data)

@app.route('/run_test/<tool>', methods=['POST'])
def run_test(tool):
    """Run specific tests on demand."""
    if tool == 'ping':
        host = request.form.get('host', '8.8.8.8')
        result = ping_host(host)
        return jsonify({'ping_result': result})
    elif tool == 'performance':
        host = request.form.get('host', '8.8.8.8')
        measure_performance(host)
        return jsonify({'status': 'Performance test started'})
    elif tool == 'speed_test':
        threading.Thread(target=run_speed_test, daemon=True).start()
        return jsonify({'status': 'Speed test started'})
    return jsonify({'status': 'Invalid tool'})

def start_monitoring():
    """Start monitoring threads."""
    interface = 'eth0'  # Default interface, change as needed
    threading.Thread(target=monitor_bandwidth, args=(interface,), daemon=True).start()
    threading.Thread(target=sniff_packets, args=(interface,), daemon=True).start()
    threading.Thread(target=measure_latency, daemon=True).start()

if __name__ == '__main__':
    start_monitoring()
    app.run(debug=True, host='0.0.0.0', port=5000)
