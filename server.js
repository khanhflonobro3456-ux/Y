// Khởi tạo các module hệ thống
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Kích hoạt Helmet thiết lập 11 lớp HTTP header bảo mật
// Ngăn chặn các luồng tấn công XSS, Clickjacking và Sniffing
app.use(helmet());

// Thiết lập lá khiên Rate Limit (Cấu hình giới hạn tần suất nghiêm ngặt)
// Thông số chặn lưu lượng: Chỉ cho phép 30 yêu cầu mỗi 15 phút từ một địa chỉ IP
const defenseShield = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: 'TỪ CHỐI KẾT NỐI: Tần suất yêu cầu vượt ngưỡng. Khiên chắn đã kích hoạt thao tác DROP.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Triển khai khiên chắn cho toàn bộ hệ thống định tuyến
app.use(defenseShield);

// Giao diện kiểm tra phản hồi của máy chủ
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
      <meta charset="UTF-8">
      <title>Hệ Thống Phòng Thủ</title>
      <style>
        body { background-color: #000; color: #0f0; font-family: monospace; text-align: center; margin-top: 15%; }
        h1 { font-size: 3em; letter-spacing: 2px; text-transform: uppercase; }
      </style>
    </head>
    <body>
      <h1>Tường lửa bảo mật trực tuyến</h1>
      <p>Trạng thái: Máy chủ Node.js đang hoạt động. Cấu hình bảo vệ: TỐI ĐA.</p>
    </body>
    </html>
  `);
});

// Cấu hình cổng kết nối theo định tuyến của môi trường Render
const PORT = process.env.PORT || 3000;

// Khởi chạy hệ thống lắng nghe lưu lượng mạng
app.listen(PORT, () => {
  console.log(`[HỆ THỐNG] Máy chủ phòng thủ đang hoạt động tại cổng: ${PORT}`);
});
