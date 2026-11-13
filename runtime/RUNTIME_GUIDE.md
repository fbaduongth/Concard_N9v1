# Thư mục Node.js Portable Runtime (`runtime/`)

Kho mã nguồn đi kèm sẵn gói nén **`runtime/node_portable.zip`** (Node.js LTS v22 dành cho Windows x64) để người dùng tải mã nguồn trực tiếp từ GitHub (`Code -> Download ZIP` hoặc `git clone`) có thể **chạy ngay lập tức 100% Offline mà không cần cài đặt Node.js**.

Khi chạy `start_collector.bat`, hệ thống tự động xử lý theo thứ tự ưu tiên:

1. **Sử dụng trực tiếp `runtime/node.exe`** nếu đã có sẵn.
2. **Tự động giải nén Offline từ `runtime/node_portable.zip` -> `runtime/node.exe`** trong ~2 giây ở lần chạy đầu tiên.
3. **Dự phòng:** Nếu xóa `node_portable.zip`, script tự động dùng `node` cài sẵn trên hệ thống hoặc tải lại bản Portable từ `nodejs.org`.
