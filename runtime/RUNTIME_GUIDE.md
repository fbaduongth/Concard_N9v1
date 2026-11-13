# Thư mục Node.js Portable Runtime (`runtime/`)

File khởi chạy `start_collector.bat` hỗ trợ tự động nhận diện môi trường theo thứ tự ưu tiên:

1. **Chạy Portable không cần cài đặt:** Nếu có file `runtime/node.exe` trong thư mục này (có sẵn trong bản đóng gói Release `Concard_N9v1_v1.1_Portable.zip`), phần mềm sẽ sử dụng trực tiếp mà không yêu cầu cài đặt Node.js trên Windows.
2. **Chạy bằng Node.js hệ thống:** Nếu không có `runtime/node.exe`, script tự động gọi lệnh `node` đã cài đặt trên máy chủ.
