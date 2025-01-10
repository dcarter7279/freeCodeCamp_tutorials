import streamlit as st 
import pandas as pd
import plotly.express as px 
import plotly.graph_objects as go 
from scapy.all import *
from collections import defaultdict 
import time
from datetime import datetime
import threading
import warnings
import logging
from typing import Dict, List, Optional
import socket
from sklearn.ensemble import IsolationForest
import geoip2.database

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""
    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.anomaly_model = None # Initalize anamaly_model attribute
        
    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'Other({protocol_num})')
    
    def map_ip_to_location(self, ip_address: str) -> tuple:
        """Map IP address geographical location"""
        try:
            response = self.geoip_reader.city(ip_address)
            return response.country.name, response.city.name
        except:
            return None, None
        
    def add_geolocation_data(df: pd.DataFrame):
        """Add geographical location data to the dataframe"""
        df['source_country'], df['source_city'] = zip(*df['source'].apply(map_ip_to_location))
        df['destination_country'], df['destination_city'] = zip(*df['destination'].apply(map_ip_to_location))
        return df
        
    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds(),
                        'payload': str(packet[TCP].payload) if TCP in packet else None
                    }
                    
                    # Add geographical data
                    packet_info['source_country'], packet_info['source_city'] = self.map_ip_to_location(packet[IP].src)
                    packet_info['destination_country'], packet_info['destination_city'] = self.map_ip_to_location(packet[IP].dst)
                    
                    
                    # Add TP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })
                    self.packet_data.append(packet_info)
                    self.packet_count += 1
                    
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
            
    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to pandas DataFrame"""
        with self.lock:
            df = pd.DataFrame(self.packet_data)
            logging.info(f"DataFrame shape: {df.shape}") # Log DataFrame shape
            return pd.DataFrame(self.packet_data)
        
    def train_anomaly_detection_model(self, df: pd.DataFrame) -> pd.DataFrame:
        """Train an Isolation model for anomaly model"""
        features = df[['size', 'src_port', 'dst_port', 'time_relative']]
        self.anomaly_model = IsolationForest(contamination=0.01)
        self.anomaly_model.fit(features)
    
    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect anomalies in the packet data using the trained IsolationForest model"""
        if self.anomaly_model is None:
            self.train_anomaly_detection_model(df)  # Train the model if not already trained

        # Select features for anomaly detection
        features = df[['size', 'src_port', 'dst_port', 'time_relative']]

        # Predict anomalies
        predictions = self.anomaly_model.predict(features)
        df['anomaly'] = predictions.reshape(-1, 1)  # Reshape the prediction array

        # Return only the rows flagged as anomalies
        return df[df['anomaly'] == -1]


def generate_alerts(df: pd.DataFrame) -> List[str]:
    """Genrate custom alerts based on traffic patterns"""
    alerts = []
    
    if df.empty:
        return alerts # Return empty list if DataFrame is empty
    
    # Example rule: High packet rate from a single IP
    ip_packet_counts = df['source'].value_counts()
    for ip, count in ip_packet_counts.items():
        if count > 1000:  # Threshold for high packet rate
            alerts.append(f"High packet rate from IP: {ip} {count} packets")
            
    # Example rule: Unusual protocol usage
    protocol_counts = df['protocol'].value_counts()
    for protocol, count in protocol_counts.items():
        if protocol == 'ICMP' and count > 1000: # Threshold for high packet rate
            alerts.append(f"Unusual ICMP traffic: {count} packets")
            
    # Example rule: Large payload size
    if 'payload' in df.columns:
        large_payloads = df[df['payload'].apply(lambda x: len(str(x)) > 1000)]  # Threshold for large payload
        if len(large_payloads) > 0:
            alerts.append(f"Large payload detected in {len(large_payloads)} packets")

    return alerts



def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title='Protocol Distribution',
        )
        st.plotly_chart(fig_protocol, use_container_width=True)
        
        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,\
            title='Packets Timeline (per second)'
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)
        
        # Geographical map visualization
        if 'source_country' in df.columns:
            country_counts = df['source_country'].value_counts().reset_index()
            country_counts.columns = ['country', 'count']
            fig_map = px.choropleth(
                country_counts,
                locations='country',
                locationmode='country names',
                color='count',
                title='Packet Sources by Country'
            )
            st.plotly_chart(fig_map, use_container_width=True)

def start_packet_capture():
    """Start packet capture in a seperate thread"""
    processor = PacketProcessor()
    
    def capture_packets():
        sniff(prn=processor.process_packet, store=False)
        
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    
    return processor

def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Dashboard", layout="wide")
    st.title("Network Traffic Dashboard")
    
    # Initialize packet processor in seesion state
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()
        
    # Create dashboard layout
    col1, col2 = st.columns(2)
    
    # Get current data
    df = st.session_state.processor.get_dataframe()
    
    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration: 2f}s")
        
    # Display visualizations
    create_visualizations(df)
    
    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )
        
    # Anomaly Detection
    st.subheader("Anomaly Detection")
    if len(df) > 0:
        anomalies = st.session_state.processor.detect_anomalies(df)
        if len(anomalies) > 0:
            st.write("Detected Anomalies:")
            st.dataframe(anomalies, use_container_width=True)
        else:
            st.write("No anomalies detected.")

    # Custom Alerts
    st.subheader("Custom Alerts")
    alerts = generate_alerts(df)
    if alerts:
        for alert in alerts:
            st.warning(alert)
    else: 
        st.info("No alerts generated.")
        
    # Packets Payload Analysis
    st.subheader("Packet Payload Analysis")
    if len(df) > 0 and 'payload' in df.columns:
        st.write("Payload Analysis Options:")
        
        # Option 1: Display payloads with large sizes
        large_payloads = df[df['payload'].apply(lambda x: len(str(x)) > 1000)]
        if len(large_payloads) > 0:
            st.write(f"Packets with large payloads (>1000 bytes): {len(large_payloads)}")
            st.dataframe(large_payloads[['timestamp', 'source', 'destination', 'protocol', 'size', 'payload']], use_container_width=True)
        else:
            st.write("No packets with large payloads detected.")
         
         # Option 2: Search for specific keywords in payloads
        keyword = st.text_input("Search for a keyword in payloads:")
        if keyword:
            matching_packets = df[df['payload'].apply(lambda x: keyword.lower() in str(x).lower())]
            if len(matching_packets) > 0:
                st.write(f"Packets containing the keyword '{keyword}':")
                st.dataframe(matching_packets[['timestamp', 'source', 'destination', 'protocol', 'size', 'payload']], use_container_width=True)
            else:
                st.write(f"No packets contain the keyword '{keyword}'.")
                   
    # Add refresh button
    if st.button("Refresh Data"):
        st.rerun()
        
    # Auto refresh
    time.sleep(2)
    st.rerun()

if __name__ == "__main__":
    main()