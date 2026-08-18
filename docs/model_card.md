# Model Card — GraphCodeBERT Verifier (Layer 3)

## Phạm vi ngôn ngữ được hỗ trợ

## Dữ liệu huấn luyện

## Hiệu năng (accuracy, precision, recall, F1)

## Giới hạn và rủi ro đã biết

### False positive hệ thống trên họ hàm buffer/format an toàn (C/C++) — xác nhận 2026-08-18

**Triệu chứng:** Model gán confidence cao (>0.5, hầu hết >0.7, nhiều case ~0.97)
và `label=1` ("CÓ LỖI") cho các lời gọi `strncpy`/`snprintf`/`memcpy`/`printf`-family
đã dùng **đúng cách, có giới hạn kích thước rõ ràng**, ngoài xa `uncertain_zone`
của cả `c` (`[0.52, 0.68]`) và `cpp` (`[0.02, 0.18]`) — tức model không "phân vân",
mà tự tin sai.

**Điều tra:** Nghi vấn ban đầu là do 2 sample gốc (`bounded_copy.c`/`.cpp`) viết
tay quá tối giản (chỉ 1 hàm `main`/`copy_input` ngắn), khác xa phong cách code
thật lấy từ GitHub commit trong dữ liệu train. Để phân biệt "vấn đề hệ thống"
với "nhiễu do 2 sample cụ thể", đã bổ sung 5 sample an toàn đa dạng hơn — dài
hơn, có include chuẩn, tên biến tự nhiên, logic xung quanh thật (parse config,
validate return value, error handling) — và 1 sample C++ idiomatic hoàn toàn
không dùng buffer thô (`std::vector`/`std::string`, bound lấy từ `.size()` thật):

| File | Sink | Cách dùng | Confidence | Label |
|---|---|---|---|---|
| `safe/c/bounded_strncpy_realistic.c` | `strncpy` ×2 | Giới hạn theo buffer đích thật, có parse/validate xung quanh | 0.967 | 1 (CÓ LỖI) |
| `safe/c/bounded_strncpy_realistic.c` | `printf` | In giá trị đã parse, không liên quan buffer | 0.771 | 1 (CÓ LỖI) |
| `safe/c/validated_snprintf.c` | `snprintf` | Kiểm tra return value để phát hiện truncation | 0.778 | 1 (CÓ LỖI) |
| `safe/c/validated_snprintf.c` | `fprintf` | Ghi log ra stderr, không có input chưa validate | 0.694 | 1 (CÓ LỖI) |
| `safe/cpp/bounded_strncpy_realistic.cpp` | `strncpy` ×2 | Tương tự bản C | 0.969 | 1 (CÓ LỖI) |
| `safe/cpp/validated_snprintf.cpp` | `snprintf` | Tương tự bản C | 0.852 | 1 (CÓ LỖI) |
| `safe/cpp/idiomatic_string_buffer.cpp` | `memcpy` | **Không có buffer thô nào** — copy vào `std::vector<char>` đã `resize()` đúng bằng `payload.size()`, bound lấy từ chính kích thước nguồn/đích thật | 0.870 | 1 (CÓ LỖI) |

**Kết quả: 9/9 (100%) candidate mới đều bị flag confidence cao, label=1**, kể cả
case C++ idiomatic không có bug-pattern nào để đối chiếu (chỉ có 1 lời gọi
`memcpy` với bound đúng 100% theo kích thước container thật).

**Kết luận: đây là vấn đề hệ thống của model, không phải nhiễu/đặc thù của 1-2
sample cụ thể.** Model dường như học được sự tương quan giữa **sự xuất hiện**
của tên hàm họ buffer/format C (`strncpy`, `snprintf`, `memcpy`, `printf`-family)
với nhãn "vulnerable", thay vì học được ngữ nghĩa "có bound đúng hay không".
Giả thuyết nhiều khả năng nhất: dữ liệu train thiên lệch (mất cân bằng) —
thiếu đủ ví dụ "âm tính" (các hàm này được dùng đúng cách, có validate/bound
rõ ràng) so với ví dụ "dương tính" (dùng sai, không giới hạn).

**Tác động thực tế:** Với threshold hiện tại của C (`0.6`) và C++ (`0.1`), hầu
hết code C/C++ dùng các hàm này — kể cả dùng đúng — sẽ bị báo `error` trong
SARIF. Layer 3 gần như không lọc được false positive nào cho nhóm sink này ở
2 ngôn ngữ C/C++, làm giảm mạnh giá trị thực tế của cascade so với kỳ vọng
thiết kế ban đầu (lọc false positive từ Layer 2).

**Việc CHƯA làm ở lần điều tra này (có chủ đích, chờ quyết định)**: không sửa
model, không sửa threshold — chỉ thu thập bằng chứng. Hướng khắc phục khả dĩ
cho bước sau: (1) rà lại/bổ sung dữ liệu train với nhiều ví dụ "dùng đúng cách"
hơn cho riêng nhóm buffer/format C, (2) hiệu chỉnh lại threshold C/C++ dựa trên
phân bố confidence thực tế trên tập test đa dạng hơn (không chỉ vulnerable
samples), (3) cân nhắc feature/signal bổ sung ngoài text thuần (vd. có phép
tính bound rõ ràng hay không) nếu (1)+(2) không đủ.

## Quy trình cập nhật model
