import os
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from flask import Flask, render_template, request, send_file
import asyncio

app = Flask(__name__)

# Function to parse the pcap file and analyze network traffic
def parse_pcap(file_path):
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture = pyshark.FileCapture(file_path, use_json=True)
    
    ip_addresses = []
    ports = []
    protocols = []
    packets = []
    
    for packet in capture:
        packet_data = {
            'time': packet.sniff_time,
            'protocol': packet.highest_layer,
            'length': int(packet.length),
            'source': packet.ip.src if 'IP' in packet else None,
            'destination': packet.ip.dst if 'IP' in packet else None
        }
        packets.append(packet_data)
        
        # Collecting IP addresses, protocols, and ports for additional analysis
        if 'IP' in packet:
            ip_addresses.append(packet.ip.src)
            ip_addresses.append(packet.ip.dst)
        
        if 'TCP' in packet or 'UDP' in packet:
            if 'TCP' in packet:
                ports.append(packet.tcp.srcport)
                ports.append(packet.tcp.dstport)
            if 'UDP' in packet:
                ports.append(packet.udp.srcport)
                ports.append(packet.udp.dstport)
        
        if 'ICMP' in packet:
            protocols.append('ICMP')
        else:
            protocols.append(packet.highest_layer)
    
    # Return both the DataFrame and the additional data for plotting
    return pd.DataFrame(packets), ip_addresses, ports, protocols

# Function to generate a protocol distribution visualization
def generate_protocol_distribution(df):
    protocol_counts = df['protocol'].value_counts()
    plt.figure(figsize=(10, 6))
    protocol_counts.plot(kind='bar', color='skyblue')
    plt.title('Protocol Distribution in Network Traffic')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig('static/protocol_distribution.png')

# Function to generate a top IPs plot
def generate_top_ips_plot(ip_addresses):
    ip_counts = pd.Series(ip_addresses).value_counts().head(10)  # Top 10 IPs
    plt.figure(figsize=(10, 6))
    ip_counts.plot(kind='bar', color='lightcoral')
    plt.title('Top 10 IPs by Packet Count')
    plt.xlabel('IP Address')
    plt.ylabel('Packet Count')
    plt.tight_layout()
    plt.savefig('static/top_ips.png')

# Function to generate a port distribution plot
def generate_ports_plot(ports):
    port_counts = pd.Series(ports).value_counts().head(10)  # Top 10 ports
    plt.figure(figsize=(10, 6))
    port_counts.plot(kind='bar', color='lightgreen')
    plt.title('Top 10 Ports by Traffic')
    plt.xlabel('Port Number')
    plt.ylabel('Packet Count')
    plt.tight_layout()
    plt.savefig('static/ports_distribution.png')

def generate_time_series_plot(df):
    # Resampling packets by time to count the number of packets per second
    df.set_index('time', inplace=True)  # Set 'time' as the index for resampling
    time_series = df['protocol'].resample('S').count()  # Count packets per second
    plt.figure(figsize=(10, 6))
    time_series.plot(color='purple')
    plt.title('Packet Count Over Time')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.tight_layout()
    plt.savefig('static/time_series_plot.png')

# Route for uploading and analyzing the pcap file
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.pcap'):
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)
            df, ip_addresses, ports, protocols = parse_pcap(file_path)
            
            # Generate visualizations
            generate_protocol_distribution(df)
            generate_top_ips_plot(ip_addresses)
            generate_ports_plot(ports)
            generate_time_series_plot(df)

            # Render the template with the generated images
            return render_template('index.html', 
                                   image_file_protocol='static/protocol_distribution.png',
                                   image_file_ips='static/top_ips.png',
                                   image_file_ports='static/ports_distribution.png',
                                   image_file_time_series='static/time_series_plot.png',
                                   data=df.to_html())
    
    return render_template('index.html', image_file_protocol=None, image_file_ips=None, image_file_ports=None, image_file_time_series=None)

# Route to download the analyzed pcap file or data
@app.route('/download')
def download():
    return send_file('static/protocol_distribution.png', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, threaded=False)
