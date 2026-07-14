const cluster = require('cluster');
const os = require('os');

// Cơ chế tự động phục hồi: Khởi tạo kiến trúc đa nhân (Multi-core Cluster)
// Đảm bảo hệ thống không bao giờ sập hoàn toàn. Nếu một tiến trình bị quá tải và chết,
// tiến trình chủ (Master) sẽ ngay lập tức tái sinh một tiến trình mới.
if (cluster.isPrimary) {
  const numCPUs = os.cpus().length;
  console.log(`[HỆ THỐNG CHỦ] Khởi động PID ${process.pid} với ${numCPUs} luồng xử lý.`);

  // Khởi tạo các tiến trình con (Worker)
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  // Lắng nghe sự kiện sập tiến trình và tự động khởi động lại ngay lập tức
  cluster.on('exit', (worker, code, signal) => {
    console.log(`[CẢNH BÁO] Luồng xử lý PID ${worker.process.pid} đã sập. Đang tái sinh...`);
    cluster.fork();
  });
} else {
  // Khởi tạo tiến trình con
  const express = require('express');
  const helmet = require('helmet');
  const rateLimit = require('express-rate-limit');
  const cors = require('cors');
  const hpp = require('hpp');
  const xss = require('xss-clean');
  const mongoSanitize = require('express-mongo-sanitize');

  const app = express();

  // Danh sách IP bị đưa vào danh sách đen (Blacklist) vĩnh viễn trong phiên
  const blacklistedIPs = new Set();

  // KHIÊN 1: Kiểm tra Blacklist ở cấp độ cao nhất. 
  // Hủy kết nối TCP ngay lập tức (TCP Reset), không phản hồi HTTP, tiêu hao tài nguyên của kẻ tấn công.
  app.use((req, res, next) => {
    if (blacklistedIPs.has(req.ip)) {
      return req.socket.destroy();
    }
    next();
  });

  // KHIÊN 2: Cấu hình giới hạn tần suất cực đoan (Rate Limit)
  // Nếu vượt quá 100 request, IP sẽ bị khóa và đưa vào Blacklist.
  const absoluteShield = rateLimit({
    windowMs: 60 * 1000, // Khung thời gian 1 phút
    max: 100, // Ngưỡng tối đa
    standardHeaders: false,
    legacyHeaders: false,
    handler: (req, res) => {
      blacklistedIPs.add(req.ip);
      req.socket.destroy(); // Phá hủy socket ngay lập tức
    }
  });
  app.use(absoluteShield);

  // KHIÊN 3: Ép giới hạn kích thước Payload siêu nhỏ (1KB)
  // Chặn đứng các gói tin lớn nhằm làm tràn bộ đệm.
  app.use(express.json({ limit: '1kb' }));
  app.use(express.urlencoded({ extended: true, limit: '1kb' }));

  // KHIÊN 4: HTTP Header Protection (Helmet)
  app.use(helmet({
    contentSecurityPolicy: true,
    dnsPrefetchControl: true,
    expectCt: true,
    frameguard: true,
    hidePoweredBy: true,
    hsts: true,
    ieNoOpen: true,
    noSniff: true,
    permittedCrossDomainPolicies: true,
    referrerPolicy: true,
    xssFilter: true
  }));

  // KHIÊN 5: Cấm toàn bộ yêu cầu Cross-Origin ngoại lai (CORS)
  app.use(cors({ origin: false }));

  // KHIÊN 6: Khử trùng dữ liệu đầu vào chống NoSQL Injection
  app.use(mongoSanitize());

  // KHIÊN 7: Vô hiệu hóa mã độc XSS
  app.use(xss());

  // KHIÊN 8: Ngăn chặn thao túng tham số HTTP (Parameter Pollution)
  app.use(hpp());

  // KHIÊN 9: Lọc phương thức HTTP nghiêm ngặt
  // Chỉ cho phép GET, hủy bỏ toàn bộ POST/PUT/DELETE từ bên ngoài
  app.use((req, res, next) => {
    if (req.method !== 'GET') {
      blacklistedIPs.add(req.ip);
      return req.socket.destroy();
    }
    next();
  });

  // Định tuyến gốc
  app.get('/', (req, res) => {
    res.status(200).send('HỆ THỐNG HOẠT ĐỘNG. LỚP GIÁP CẤP ĐỘ CAO NHẤT ĐÃ KÍCH HOẠT.');
  });

  // KHIÊN 10: Xử lý các tuyến đường không xác định
  // Bất kỳ truy vấn nào dò quét hệ thống đều bị hủy kết nối TCP ngay lập tức
  app.all('*', (req, res) => {
    req.socket.destroy();
  });

  const PORT = process.env.PORT || 3000;
  const server = app.listen(PORT, () => {
    console.log(`[LUỒNG ${process.pid}] Đang hoạt động tại cổng ${PORT}.`);
  });

  // Cấu hình Timeout cấp thấp chống ngâm kết nối (Slowloris)
  server.setTimeout(2000); // Ngắt kết nối toàn bộ sau 2 giây
  server.keepAliveTimeout = 2000;
  server.headersTimeout = 2500;
}
