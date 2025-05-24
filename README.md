# 🔐 RSA Digital Signature Web App

This project is a web-based application that allows users to digitally sign and verify files using **RSA digital signatures**. It is built with **Python (Flask)** and styled using **Bootstrap 5** and **FontAwesome**.

---

## 🌟 Features

- 🔏 Sign any file using RSA private key
- ✅ Verify file authenticity using digital signature
- 🗝️ Generate RSA key pairs (Sender / Receiver / Custom users)
- 📂 View and download signed & verified files
- 📦 Export all RSA keys as a ZIP archive
- 💡 Clean, responsive and animated UI

---


## 📁 Project Structure

WEB_CHU-KI-SO1/
│
├── keys/
│
│ ├── receiver_private.pem
│ ├── receiver_public.pem
│ ├── sender_public.pem
│ ├── sender_private.pem
│
│
├── received_files/_
│ └── 
│
├── signed_file
│ └── (nơi chứa thông tin về file sau khi ký)
│
├── upl
│ └── (file upload)
│
├── user_keys/_
│
├── templ
│ ├── generate_key.html
│ ├── base.html
│ ├── index.html
│ ├── sender.html
│ ├── receiver.html
│
│
├── main.py # File chính chạy Flask app
└── README.md # Tài liệu dự án


---

## ⚙️ Hướng dẫn cài đặt

### 1. Cài đặt môi trường ảo dự án
cd WEB_CHU-KI-SO1
python -m venv venv
source venv/bin/activate     # Linux/macOS
venv\Scripts\activate        # Windows

### 2. Cài thư viện
py -m pip install flask-wtf  

### 3. Chạy ứng dụng
python main.py

Ứng dụng sẽ chạy tại: http://localhost:5000

🔐 Chức năng bảo mật
Khóa riêng được lưu nội bộ (không chia sẻ ra ngoài)

Chữ ký sử dụng SHA-256 kết hợp với RSA-PSS

File .info chứa:
+ Tên tệp
+ Signature (base64)
+ File hash (SHA-256)
+ Dung lượng
+ Thời gian ký

📦 Xuất cặp khóa
Bạn có thể tải toàn bộ khóa mặc định (sender/receiver) bằng đường dẫn:
   http://localhost:5000/download_keys

📜 Giấy phép
Dự án được phát hành dưới giấy phép MIT License – sử dụng tự do cho mục đích học tập hoặc mở rộng thương mại.

👨‍💻 Tác giả
Developed by Lich

## 🖥️ Demo UI
![image](https://github.com/user-attachments/assets/da1c8efe-a2e5-47ac-8341-0a40550a0852)
![image](https://github.com/user-attachments/assets/9c60e97d-ba48-40ae-83b5-6b4ab6c8997c)
![{1C33C4B2-BCE3-42AE-BDF3-6D1BC1DE367F}](https://github.com/user-attachments/assets/b022fddf-2a99-4fdf-8f44-4d5708feb197)
![image](https://github.com/user-attachments/assets/d218d3ec-d577-4370-8e83-2299b617566e)
![image](https://github.com/user-attachments/assets/79672458-258a-474e-ac39-71590541b48d)



