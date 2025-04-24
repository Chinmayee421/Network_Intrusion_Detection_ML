# 🔐 Network Intrusion Detection using Machine Learning

This project implements a machine learning-based Network Intrusion Detection System (NIDS) to classify network traffic as normal or malicious using the CICIDS2017 dataset.  
The goal is to enhance cybersecurity by identifying intrusions through intelligent data analysis.

## 📌 Features

- 📊 Exploratory Data Analysis (EDA)  
- 🧹 Data Preprocessing and Cleaning  
- ✂️ Feature Selection using RFE (Recursive Feature Elimination)  
- 🧠 Machine Learning Models for Classification  
- 📈 Model Evaluation Metrics  
- 💾 Model Serialization using Pickle  
- 🖥 Streamlit UI for user interaction  
- ☁️ Azure Web App for deployment  

## 🖼️ UI Screenshots

### 🔹 Home Interface and Prediction Result
![Screenshot 2025-02-12 101424](https://github.com/user-attachments/assets/b0428269-9219-43b8-9622-d28e27093d13)

![WhatsApp Image 2025-02-11 at 22 48 49](https://github.com/user-attachments/assets/27228963-350e-48db-91c3-bd71a522fbb6)


## 📁 Dataset

- **Source**: [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)  
- Real-world traffic data with both normal and various types of attack behaviors.  
- Includes over 70 features like `Flow Duration`, `Bwd Packet Length Std`, `Fwd Packet Length Max`, `Packet Length Variance`, etc.

## 🛠️ Tech Stack

- **Programming Language** – 🐍 Python  
- **Libraries & Frameworks** – 📊 Pandas, 🔢 NumPy, 🤖 Scikit-learn, 🎨 Matplotlib / Seaborn  
- **Feature Selection Methods** – 🔍 RFE (Recursive Feature Elimination)  
- **Model Deployment** – 🗂 Pickle (for model storage)  
- **UI** – 🖥 Streamlit  
- **Cloud & Hosting** – 🌍 Azure Web App Services, GitHub (for version control & deployment)

## ☁️ Azure & GitHub Deployment

- Model deployed using **Azure Web App Services**  
- Source code and version control managed via **GitHub**
🔗 [Live Demo]([https://your-app-name.azurewebsites.net](https://team6-bvbyh6fnehded7gp.centralus-01.azurewebsites.net/))

## 🧠 Future Enhancements

- Deploy deep learning models (LSTM, CNN, etc.)
- Incorporate real-time detection via Spark Streaming.
- Add anomaly detection capabilities
