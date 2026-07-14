// Khởi tạo các module hệ thống
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const hpp = require('hpp');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();

// 1. Giới hạn kích thước payload cực nhỏ (1KB)
// Chặn ngay lập tức các gói dữ liệu khổng lồ nhằm gây tràn bộ nhớ (Buffer Overflow/DDoS)
app.use(express.json({ limit: '1kb' }));
app.use(express.urlencoded({ extended: true, limit: '1kb' }));

// 2. Kích hoạt Helmet với tất cả các lớp bảo mật HTTP Header
app.use(helmet());

// 3. Ngăn chặn NoSQL Injection
app.use(mongoSanitize());

// 4. Ngăn chặn XSS (Cross-Site Scripting) xóa mã độc trong nội dung gửi đến
app.use(xss());

// 5. Ngăn chặn HTTP Parameter Pollution (Gửi mảng tham số giả mạo)
app.use(hpp());

// 6. Cấu hình CORS nghiêm ngặt: Từ chối mọi request từ tên miền bên ngoài
app.use(cors({ origin: false })); 

// 7. Tường lửa Rate Limit cực đại (Khóa vĩnh viễn sau 100 request)
const superShield = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // Theo dõi trong 24 giờ
  max: 100, // Cắt đứt hoàn toàn khi chạm mốc 100 request
  standardHeaders: false,
  legacyHeaders: false,
  handler: (req, res) => {
    // DROP kết nối ngay lập tức, không xử lý, không gửi thông báo
    req.socket.destroy();
  }
});

// Áp dụng lớp giáp cho toàn bộ hệ thống định tuyến
app.use(superShield);

// 8. Tắt định danh máy chủ
app.disable('x-powered-by');

// Tuyến đường gốc
app.get('/', (req, res) => {
  res.status(200).send('HỆ THỐNG HOẠT ĐỘNG. LỚP GIÁP CẤP ĐỘ CAO NHẤT ĐÃ KÍCH HOẠT.');
});

// Xử lý và Hủy (DROP) các route không tồn tại để tránh bị dò quét (Scanning)
app.all('*', (req, res) => {
  req.socket.destroy();
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`[HỆ THỐNG] Khởi động tại cổng ${PORT}.`);
});

// 9. Cấu hình Timeout Cực Đoan (Ngăn chặn Slowloris DDoS)
// Ngắt kết nối nếu không nhận đủ dữ liệu trong 3 giây
server.setTimeout(3000); 
server.keepAliveTimeout = 3000;
server.headersTimeout = 4000;
