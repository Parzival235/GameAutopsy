# GameAutopsy

Trình đọc cấu trúc file game chạy trên thiết bị. Mở [GameAutopsy trên GitHub Pages](https://parzival235.github.io/GameAutopsy/), kéo file vào trang rồi chọn vùng cần xem. Dùng **Mở** để đi vào một mục ZIP, **Hex** để nhảy tới offset và **Tải báo cáo JSON** để lưu phân tích của file đang xem.

| Định dạng | Dữ liệu đọc được |
| --- | --- |
| ZIP, APK, APKS, XAPK, AAB, IPA, OBB có chữ ký ZIP | Central directory và ZIP64 một đĩa, cờ, phương thức nén, kích thước, CRC32 và offset local header. Mở mục Stored hoặc Deflate và xác minh CRC32 khi đọc. |
| DEX | Header, bảng ID và định nghĩa lớp, DEX map. DEX 041 trở lên hiển thị header đầu. |
| ELF 32/64 | Entry VA, segment, section, kiến trúc, endianness và offset trong file. |
| PE32 / PE32+ | Kiến trúc, entry RVA, image base, section và data directory. |
| UnityFS | Phiên bản engine, kích thước bundle, kiểu nén và vị trí vùng blocks info. |
| Android binary XML | Loại, kích thước, offset và số dòng của chunk khi có. |
| Godot PCK / IL2CPP metadata | Nhận dạng chữ ký và một số trường đầu file. |
| Mọi file | Hex, entropy ở hai đầu, mẫu chuỗi ASCII/UTF-16LE, SHA-256 theo yêu cầu. |

Offset tính từ đầu file đang xem. Offset của một mục ZIP trong bảng trỏ tới local header của mục đó. Khi mở mục, phần **Chi tiết định dạng và nguồn** cho biết offset của local header và offset bắt đầu dữ liệu trong gói cha. Các cột offset và kích thước báo cáo JSON dùng byte và số hệ 10. Địa chỉ ảo được ghi dưới dạng chuỗi hex. Mỗi báo cáo ghi rõ đường dẫn qua các lớp gói, cảnh báo và số vùng thực tế đã đọc.

## Dữ liệu và giới hạn

- Trang chỉ tải HTML, CSS và JavaScript từ nơi chứa trang. Công cụ đọc file chỉ đọc bằng File API, xử lý bằng Web Worker và tạo báo cáo ngay trên thiết bị. File gốc, tên file và báo cáo không được truyền qua mạng. Không có backend, analytics hay thư viện từ CDN.
- Muốn mở cả trang khi mất mạng, tải mã nguồn rồi phục vụ trên localhost. Trang tải từ Pages vẫn cần kết nối khi tải lại.
- Danh mục ZIP có giới hạn 20.000 mục và 24 MiB dữ liệu danh mục. Mở tối đa 6 tầng gói lồng nhau, 128 MiB mỗi mục và 256 MiB cho các mục đang mở. Hash toàn file hỗ trợ đến 256 MiB. Chuỗi được lấy từ 4 MiB đầu, tối đa 500 kết quả.
- Công cụ đọc cấu trúc tĩnh. DEX ở mức bảng, UnityFS ở mức header và vùng danh mục. ZIP mã hóa, ZIP chia đĩa và phương thức nén khác Stored/Deflate hiện chưa mở được.

## Chạy từ bản fork hoặc bản tải xuống

Cần trình duyệt hiện đại hỗ trợ Web Worker dạng module, Web Crypto và `DecompressionStream('deflate-raw')`. Tại thư mục repo, chạy lệnh sau rồi mở [http://localhost:8000](http://localhost:8000).

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

Windows có thể dùng `py -3` thay cho `python3`. Khi bật Pages cho bản fork, chọn **Settings → Pages → Deploy from a branch → main → /(root)**.

## Phát triển

`index.html` và `app.mjs` điều khiển giao diện, `worker.mjs` đọc file và quản lý các lớp gói, `formats.mjs` chứa các bộ đọc. Chạy kiểm thử với Node.js 22 trở lên.

```sh
node --test tests/*.test.mjs
```

Tài liệu định dạng [ZIP](https://support.pkware.com/pkzip/appnote), [DEX](https://source.android.com/docs/core/runtime/dex-format), [ELF](https://gabi.xinuos.com/elf/), [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) và [UnityFS](https://reverseengineering.wiki/index.php/Format:Unity_asset_bundle_(UnityFS)).

## Giấy phép

Mã nguồn được phát hành theo [Mozilla Public License 2.0](LICENSE). Khi phân phối lại các tệp được cấp phép, giữ thông báo giấy phép và cung cấp mã nguồn của các tệp được cấp phép đã sửa theo MPL. Công cụ phân tích riêng có thể chạy độc lập từ máy.
