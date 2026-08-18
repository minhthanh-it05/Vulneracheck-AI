# Model Card — GraphCodeBERT Verifier (Layer 3)

## Phạm vi ngôn ngữ được hỗ trợ

## Dữ liệu huấn luyện

## Hiệu năng (accuracy, precision, recall, F1)

### Kiểm thử trên CVE thật — 2026-08-18

Lần đầu tiên có bằng chứng thực nghiệm trên lỗ hổng đã công bố (CVE), thay vì
chỉ trên sample tự viết. Quy trình: clone repo thật tại đúng commit **trước**
khi patch (xác minh qua GitHub REST API, không chỉ dựa vào tóm tắt), chạy
`vulneracheck scan` trên file chứa lỗi, đối chiếu dòng code với commit fix
thật.

| CVE | Project | CWE | File:line | Sink | Confidence | Kết quả |
|---|---|---|---|---|---|---|
| CVE-2023-42801 | moonlight-stream/moonlight-common-c | CWE-120 | `src/Misc.c:88` | `strcpy` | **0.9347** | Phát hiện đúng |
| CVE-2026-44713 | mcdope/pam_usb | CWE-78 | `src/tmux.c:59` | `popen` | **0.9389** | Phát hiện đúng |

**Recall trên tập test: 2/2 (100%).**

**Đây là mẫu rất nhỏ (n=2) — KHÔNG đủ để tổng quát hoá thành một con số
recall chính thức cho model.** Ý nghĩa thực sự của kết quả này là: đây là
**bằng chứng thực nghiệm đầu tiên** cho thấy verifier có khả năng phát hiện
lỗ hổng thật trên code sản xuất thật (không chỉ trên fixture tự viết), không
phải một benchmark recall đáng tin cậy về mặt thống kê. Cần tập CVE lớn hơn
nhiều (hàng chục tới hàng trăm case) mới có thể công bố recall chính thức.

## Hiệu năng runtime (thời gian quét) — 2026-08-18

Đo trên CPU (không GPU), model FP32 ~476MB.

- **Overhead cố định mỗi lần chạy**: ~15-20s (load ONNX session + tokenizer),
  không phụ thuộc số file/candidate.
- **Chi phí biên tại Layer 3**: ~0.45s/candidate (đo tuyến tính ở N=10/30/60
  candidate: 5.42s/13.48s/26.59s), **sau khi vá bug batch** (xem bên dưới).
- **Trước khi vá bug**: `predict_batch()` gộp TOÀN BỘ candidate của cả lần
  quét vào 1 lần gọi ONNX Runtime duy nhất, dùng `padding=True` (pad theo
  item dài nhất trong batch). Vì Layer 2 trích full-function làm snippet
  (có thể rất dài — đo được 1 case 17.305 ký tự trong code thật), batch càng
  lớn càng dễ dính snippet dài, khiến chi phí tăng **phi tuyến tính**: N=200
  candidate trở lên không hoàn thành sau nhiều phút (đã thử timeout 3-5 phút).
  Đã sửa bằng cách thêm `MAX_BATCH_SIZE = 32` (`verifier/inference.py`) —
  chunk cố định thay vì 1 batch khổng lồ. Sau khi vá: 229 candidate hoàn
  thành trong 103s (khớp tốc độ tuyến tính đo ở N nhỏ).
- **Thời gian end-to-end thật đo được** (CLI đầy đủ, gồm cả overhead):

  | Kịch bản | File | Candidate | Thời gian |
  |---|---|---|---|
  | 1 file | 1 | 5-8 | 12-26s |
  | Thư mục nhỏ | 4 | 13 | 16.5s |
  | Thư mục vừa (sau khi vá bug) | 34 | 229 | 1m58s |

**Hàm ý cho CI/CD**: phù hợp chạy như **scheduled job** (vd. nightly scan
toàn repo). **CHƯA phù hợp làm gate chặn mỗi PR** nếu quét lại toàn bộ repo
mỗi lần trên codebase lớn — vài phút mỗi lần chạy là quá chậm cho PR check
cần phản hồi nhanh. Hướng giải quyết dự kiến cho bước sau: **scan theo diff**
(chỉ quét file/hunk thay đổi trong PR thay vì toàn repo) thay vì cố gắng tối
ưu thêm tốc độ raw của Layer 3.

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

**Củng cố thêm bằng bằng chứng trên code sản xuất thật — 2026-08-18:** quét
thư viện [`antirez/sds`](https://github.com/antirez/sds) (Simple Dynamic
Strings — thư viện chuỗi dùng trong Redis, tác giả Salvatore Sanfilippo,
không có lịch sử CVE, đã qua 15+ năm sử dụng thực tế). Kết quả: **13/13
(100%) finding** (`memcpy`, `memset`, `memmove`, `printf`, confidence
0.96–0.99) — sau khi tự đọc lại từng dòng code thật, **toàn bộ 13/13 đều là
false positive**: mọi lời gọi đều nằm sau bước cấp phát/`sdsMakeRoomFor()`
đảm bảo đủ kích thước, hoặc là format string literal an toàn. Không có ngoại
lệ nào. Đây là bằng chứng mạnh hơn cả 9/9 sample tự viết ở trên vì được đo
trên code sản xuất thật, không phải fixture tự tạo — loại hoàn toàn khả năng
"nhiễu do cách viết sample".

**Kết luận: đây là vấn đề hệ thống của model, không phải nhiễu/đặc thù của 1-2
sample cụ thể.** Model dường như học được sự tương quan giữa **sự xuất hiện**
của tên hàm họ buffer/format C (`strncpy`, `snprintf`, `memcpy`, `printf`-family)
với nhãn "vulnerable", thay vì học được ngữ nghĩa "có bound đúng hay không".
Giả thuyết nhiều khả năng nhất: dữ liệu train thiên lệch (mất cân bằng) —
thiếu đủ ví dụ "âm tính" (các hàm này được dùng đúng cách, có validate/bound
rõ ràng) so với ví dụ "dương tính" (dùng sai, không giới hạn).

**Tác động thực tế:** Với threshold hiện tại của C (`0.6`) và C++ (`0.1`), hầu
hết code C/C++ dùng các hàm này — kể cả dùng đúng — vẫn bị model gán
`label=1`. Từ sau khi thêm `LOW_CONFIDENCE_CWE_CATEGORIES` ở tầng reporting
(`reporting/__init__.py`), các finding thuộc nhóm CWE này bị ép hiển thị
`level="warning"` thay vì `"error"` trong SARIF — đây là **giảm nhẹ mức độ
ồn ào**, KHÔNG phải sửa gốc: Layer 3 vẫn đang gán `label=1` sai cho gần như
mọi lời gọi thuộc nhóm này, chỉ là hậu quả (mức độ nghiêm trọng hiển thị)
được hạ bớt, còn số lượng finding sai vẫn giữ nguyên. Giá trị thực tế của
cascade (lọc false positive từ Layer 2) gần như bằng 0 cho nhóm sink này ở
C/C++.

**Việc CHƯA làm (có chủ đích, chờ quyết định)**: không sửa model, không sửa
threshold — chỉ thu thập bằng chứng và giảm nhẹ hiển thị ở tầng reporting.
Hướng khắc phục khả dĩ cho bước sau: (1) rà lại/bổ sung dữ liệu train với
nhiều ví dụ "dùng đúng cách" hơn cho riêng nhóm buffer/format C, (2) hiệu
chỉnh lại threshold C/C++ dựa trên phân bố confidence thực tế trên tập test
đa dạng hơn (không chỉ vulnerable samples) — nay đã có thêm dữ liệu thật từ
`sds` để tham chiếu, (3) cân nhắc feature/signal bổ sung ngoài text thuần
(vd. có phép tính bound rõ ràng hay không) nếu (1)+(2) không đủ.

### False-negative gap ở Layer 2 (Tree-sitter rule) — phát hiện 2026-08-18

**Lưu ý: đây là rủi ro theo hướng NGƯỢC LẠI với false positive ở trên — bỏ
sót lỗi thật, không phải báo sai lỗi giả — không gộp chung 2 vấn đề.**

Khi chọn repo "sạch" để test false-positive rate, thử qua thư viện
[`ludocode/mpack`](https://github.com/ludocode/mpack) trước khi chọn `sds`.
Các file lõi của mpack (`mpack-reader.c`, `mpack-writer.c`, `mpack-node.c`)
gọi `memcpy`/`malloc`/`realloc` thật (xác nhận bằng `grep`), nhưng
`vulneracheck scan` trả về **0 candidate** cho các file này.

**Nguyên nhân:** mpack tự định nghĩa wrapper riêng cho các hàm libc
(`mpack_memcpy`, `mpack_realloc`, ...) thay vì gọi thẳng `memcpy`/`realloc`.
Rule `.scm` ở Layer 2 hiện chỉ match theo tên định danh **chính xác**
(`#match? @sink.name "^(memcpy|memmove|...)$"`) — `mpack_memcpy` không khớp
regex này dù về bản chất vẫn là một lời gọi copy bộ nhớ thô, cùng rủi ro như
`memcpy` trần.

**Tác động:** Bất kỳ codebase nào tự định nghĩa wrapper cho hàm buffer/memory/
format (rất phổ biến trong code C lớn — thường để thêm logging, đo đạc, hay
portability layer) sẽ **lọt hoàn toàn qua Layer 2**, không được forward lên
Layer 3, không xuất hiện trong SARIF dù có lỗi thật bên trong. Đây là false
negative ở mức triệt để nhất — không phải "confidence thấp", mà là "không
được quét tới".

**Chưa xử lý ở đợt này** — ghi nhận làm rủi ro đã biết, cần quyết định hướng
xử lý sau (vd. cho phép cấu hình alias tên hàm theo project, hoặc match theo
substring/suffix thay vì exact match — đánh đổi với nguy cơ tăng false
positive nếu match quá lỏng).

## Quy trình cập nhật model
