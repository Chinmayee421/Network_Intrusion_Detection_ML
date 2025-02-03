import streamlit as st
import joblib
import numpy as np

# Set Streamlit to use the full-screen layout
st.set_page_config(page_title="Network Intrusion Detection", layout="wide")

# Load the trained model
model = joblib.load('random_forest_model.pkl')

# Mapping PCA components back to original feature names
pca_feature_mapping = {
    'PC1': 'Idle Std', 'PC2': 'Active Max', 'PC3': 'Active Std', 'PC4': 'Active Mean',
    'PC5': 'min_seg_size_forward', 'PC6': 'act_data_pkt_fwd', 'PC7': 'Init_Win_bytes_forward',
    'PC8': 'Init_Win_bytes_backward', 'PC9': 'Down/Up Ratio', 'PC10': 'URG Flag Count',
    'PC11': 'ACK Flag Count', 'PC12': 'PSH Flag Count', 'PC13': 'RST Flag Count', 'PC14': 'FIN Flag Count',
    'PC15': 'Min Packet Length', 'PC16': 'Bwd Packets/s', 'PC17': 'Bwd Header Length',
    'PC18': 'Fwd Header Length', 'PC19': 'Fwd URG Flags', 'PC20': 'Fwd PSH Flags',
    'PC21': 'Bwd IAT Max', 'PC22': 'Bwd IAT Std', 'PC23': 'Bwd IAT Mean', 'PC24': 'Bwd IAT Total',
    'PC25': 'Fwd IAT Min', 'PC26': 'Flow IAT Min', 'PC27': 'Flow IAT Std', 'PC28': 'Flow IAT Mean',
    'PC29': 'Flow Packets/s', 'PC30': 'Flow Bytes/s', 'PC31': 'Bwd Packet Length Min',
    'PC32': 'Bwd Packet Length Max', 'PC33': 'Fwd Packet Length Mean', 'PC34': 'Fwd Packet Length Min',
    'PC35': 'Fwd Packet Length Max',
}

important_features = list(pca_feature_mapping.keys())

# Streamlit UI
st.title("🚀 Network Intrusion Detection System")
st.markdown("Enter feature values below and click **Detect Intrusion**.")

# Arrange input fields in columns
cols = st.columns(3)  # Three columns for better layout
feature_values = {}

for i, feature in enumerate(important_features):
    feature_label = pca_feature_mapping.get(feature, feature)
    feature_values[feature] = cols[i % 3].text_input(f"{feature_label}", value="0")  # Default value is "0"

# Detect intrusion
if st.button("🚨 Detect Intrusion"):
    try:
        # Convert input values to float
        feature_array = np.array([float(feature_values[feature]) for feature in important_features]).reshape(1, -1)
        
        # Predict intrusion
        prediction = model.predict(feature_array)
        
        # Display results
        if prediction[0] == 1:
            st.error("⚠️ Intrusion Detected!")
        else:
            st.success("✅ No Intrusion Detected!")
    
    except ValueError:
        st.warning("Please enter valid numerical values for all features.")
