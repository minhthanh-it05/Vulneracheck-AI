# Model Card — GraphCodeBERT Verifier (Layer 3)

## Phạm vi ngôn ngữ được hỗ trợ

Model (Layer 3) chỉ hỗ trợ **C, C++, Java** (`SUPPORTED_ML_LANGUAGES` trong
`verifier/__init__.py`). Layer 2 (rule Tree-sitter) hỗ trợ thêm **Python**
(`rules/python/python_sinks.scm`) — candidate sink Python vẫn được Layer 1+2
quét và xuất hiện trong SARIF (`ml_verified=false`, `severity="warning"`,
kèm `properties.note` giải thích), nhưng KHÔNG được Layer 3 lọc false
positive, nên độ tin cậy thấp hơn hẳn so với finding C/C++/Java đã qua model.
CLI in thêm 1 dòng cảnh báo tổng hợp mỗi khi scan có candidate thuộc nhóm
này (xem `pipeline.build_ml_unsupported_warning`).

## Dữ liệu huấn luyện

## Hiệu năng (accuracy, precision, recall, F1)

### Đánh giá độc lập trên SVEN dataset — 2026-08-19

**Nguồn dữ liệu:** [SVEN dataset trên HuggingFace](https://huggingface.co/datasets/bstee615/sven)
(repo_id `bstee615/sven`, 803 cặp before/after, kiểm tra thủ công bởi con
người). **Đây KHÔNG phải test set gốc lúc train model** (test.csv gốc lưu
trên Google Drive đã không còn truy cập được, không khôi phục lại được) —
SVEN được chọn thay thế vì là dataset ĐỘC LẬP, CHƯA TỪNG được dùng ở bất kỳ
bước nào trong pipeline train model này (không có rủi ro data leakage). Quy
trình đầy đủ, chạy lại được qua `scripts/evaluate_sven.py`:

1. Tải cả 2 split (train 720 + val 83 = 803 dòng) trực tiếp từ HuggingFace
   Hub.
2. Lọc chỉ giữ dòng có `file_name` đuôi C/C++ (Python nằm ngoài phạm vi
   model — xem mục "Phạm vi ngôn ngữ được hỗ trợ"); loại 381 dòng ngoài
   C/C++ và 4 cặp before/after thoái hoá (rỗng hoặc giống hệt nhau).
3. Dựng tập test nhị phân: `func_src_before` → label=1 (có lỗi),
   `func_src_after` → label=0 (đã fix) — 836 example, đã cân bằng sẵn 50/50
   theo từng ngôn ngữ nhờ cấu trúc cặp 1-1 (c: 362/362, cpp: 56/56).
4. Chạy `ONNXVerifier.predict_batch()` với model + threshold **giữ nguyên
   trạng** tại `weights/model.onnx` + `weights/threshold_config.json` —
   KHÔNG train lại, KHÔNG hiệu chỉnh/re-calibrate threshold ở bước này.

**Kết quả:**

| Ngôn ngữ | n | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| C | 724 | 283 | 285 | 77 | 79 | 0.4972 | 0.4982 | 0.7818 | 0.6086 |
| C++ | 112 | 55 | 54 | 2 | 1 | 0.5089 | 0.5046 | 0.9821 | 0.6667 |
| **Tổng hợp C+C++** | **836** | **338** | **339** | **79** | **80** | **0.4988** | **0.4993** | **0.8086** | **0.6174** |

**Diễn giải:** Recall cao (78-98%) — model hiếm khi bỏ sót lỗi thật. Nhưng
precision xấp xỉ 50% (gần tương đương đoán ngẫu nhiên) ở CẢ HAI ngôn ngữ,
đặc biệt C++ gần như luôn đoán label=1 (TN chỉ 2/56, tức gần như mọi hàm ĐÃ
FIX vẫn bị gán "có lỗi"). Kết quả này **khớp và định lượng ở quy mô lớn
hơn nhiều** vấn đề đã ghi nhận ở mục "False positive hệ thống trên họ hàm
buffer/format an toàn (C/C++)" bên dưới (trước đó chỉ có 9 sample tự viết +
13 sample từ `sds` — ở đây là 836 example từ nguồn độc lập, đa dạng, do con
người gán nhãn). Kết luận không đổi: model hiện tại rất tốt để KHÔNG bỏ sót
(high recall), nhưng lọc false positive (mục tiêu chính của Layer 3 trong
cascade) hiệu quả gần như bằng 0 trên C/C++ với threshold hiện tại.

**Java:** chưa có bộ đánh giá độc lập cục bộ cho ngôn ngữ này ở bước này —
SVEN không có đủ dữ liệu Java sạch để tách riêng, KHÔNG bịa số liệu. Cần bộ
dữ liệu Java độc lập riêng cho lần đánh giá sau.

#### Đối chiếu số liệu

Số liệu nội bộ đo được lúc train trước đây (ước tính ~89-91% cho C, sau khi
trừ ảnh hưởng leakage) và số liệu SVEN đo được ở trên (~50%, xấp xỉ mức đoán
ngẫu nhiên) chênh lệch rất lớn — cần nói rõ vì sao và nên tin số nào.

**Nguyên nhân chênh lệch:** con số "~89-91%" trước đó **không phải đo trực
tiếp** trên một test set sạch — đó là **suy luận gián tiếp**, dựa trên giả
định đơn giản hoá từ tỷ lệ leakage (trùng lặp/gần-trùng-lặp giữa train và
test) đo được lúc đó, rồi ước tính ngược lại hiệu năng "nếu không có
leakage" sẽ khoảng bao nhiêu. Đây là một phép ước lượng gián tiếp, không
phải kết quả thực đo trên dữ liệu mà model chưa từng thấy dưới bất kỳ hình
thức nào. Ngược lại, số liệu SVEN ở trên là **bằng chứng thực đo** — chạy
inference thật, trên nguồn dữ liệu hoàn toàn độc lập (chưa từng xuất hiện ở
bất kỳ bước nào trong pipeline train), do con người gán nhãn thủ công.

**Kết luận:** SỐ LIỆU SVEN (~50% precision) NÊN ĐƯỢC COI LÀ ĐẠI DIỆN THẬT
HƠN cho khả năng tổng quát hoá của model trên code chưa từng thấy, so với
con số nội bộ ~89-91% — con số nội bộ có nguy cơ bị thổi phồng bởi
gần-trùng-lặp giữa train/test lấy cùng nguồn (cùng phong cách code, cùng
project, đôi khi cùng hàm chỉ khác vài dòng), khiến model "nhớ" thay vì
thực sự học được ranh giới an toàn/có lỗi.

**Hàm ý thực tế:** với precision ~50% trên C/C++ ở trạng thái hiện tại,
**KHÔNG NÊN dùng Layer 3 làm căn cứ để ra quyết định tự động** (vd. tự động
block PR chỉ vì Layer 3 gán label=1) — làm vậy sẽ chặn nhầm khoảng một nửa
số PR sạch. Layer 3 chỉ nên được dùng đúng vai trò đã thiết kế trong cascade
3 lớp: một **tín hiệu ưu tiên hoá cho review thủ công** (giúp người review
biết nên nhìn kỹ finding nào trước), không phải một bộ lọc tự động đáng tin
cậy ở ngưỡng hiện tại.

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

### False-negative gap ở Layer 2 (Tree-sitter rule) — phát hiện 2026-08-18, đã vá 2026-08-18

**Lưu ý: đây là rủi ro theo hướng NGƯỢC LẠI với false positive ở trên — bỏ
sót lỗi thật, không phải báo sai lỗi giả — không gộp chung 2 vấn đề.**

Khi chọn repo "sạch" để test false-positive rate, thử qua thư viện
[`ludocode/mpack`](https://github.com/ludocode/mpack) trước khi chọn `sds`.
Các file lõi của mpack (`mpack-reader.c`, `mpack-writer.c`, `mpack-node.c`)
gọi `memcpy`/`malloc`/`realloc` thật (xác nhận bằng `grep`), nhưng
`vulneracheck scan` trả về **0 candidate** cho các file này.

**Nguyên nhân:** mpack tự định nghĩa wrapper riêng cho các hàm libc
(`mpack_memcpy`, `mpack_realloc`, ...) thay vì gọi thẳng `memcpy`/`realloc`.
Rule `.scm` ở Layer 2 khi đó chỉ match theo tên định danh **chính xác**
(`#match? @sink.name "^(memcpy|memmove|...)$"`) — `mpack_memcpy` không khớp
regex này dù về bản chất vẫn là một lời gọi copy bộ nhớ thô, cùng rủi ro như
`memcpy` trần.

**Tác động (trước khi vá):** Bất kỳ codebase nào tự định nghĩa wrapper cho
hàm buffer/memory/format (rất phổ biến trong code C lớn — thường để thêm
logging, đo đạc, hay portability layer) sẽ **lọt hoàn toàn qua Layer 2**,
không được forward lên Layer 3, không xuất hiện trong SARIF dù có lỗi thật
bên trong. Đây là false negative ở mức triệt để nhất — không phải "confidence
thấp", mà là "không được quét tới".

**Cách đã vá:** Đổi predicate `#match?` trong toàn bộ `rules/c/c_sinks.scm`
và `rules/cpp/cpp_sinks.scm` (mọi nhóm CWE, cả bản qualify `std::` lẫn
không-qualify) từ exact-match `"^(...)$"` sang
`"(^|_)(...)($|_)"` — yêu cầu tên sink là một **thành phần tách biệt bằng
underscore** trong tên hàm được gọi, không cần khớp tuyệt đối cả tên. Bắt
được `mpack_memcpy`, `my_strcpy_wrapper`, `safe_malloc`, v.v., đồng thời
**không** match nhầm tên hàm chỉ tình cờ chứa chuỗi con dính liền (vd.
`mallocator`, `freetype_init` — không có underscore phân tách nên không
khớp). Có test hồi quy cho cả 2 chiều (`test_parse_file_detects_wrapper_function_names`,
`test_parse_file_does_not_match_unrelated_function_names` trong
`tests/unit/test_parsers.py`).

**Đánh đổi chấp nhận được:** match rộng hơn = tăng false positive tiềm năng
ở Layer 2 (nhiều candidate hơn được forward lên Layer 3) — đúng theo triết
lý high-recall xuyên suốt dự án của Layer 2 (rule `malloc`/`calloc` đã áp
dụng logic match-rộng tương tự từ trước, dù với lý do khác); Layer 3
(verifier) là nơi lọc precision, không phải Layer 2.

**Giới hạn còn lại lúc đó (không giải quyết được bằng regex theo tên):**
Wrapper đặt tên **hoàn toàn không chứa** tên sink gốc như một thành phần
(vd. `safeCopy` không chứa `strcpy`/`memcpy` dưới bất kỳ dạng nào) vẫn sẽ bị
bỏ sót — đây là giới hạn cố hữu của cách tiếp cận match theo tên định danh,
chỉ giải quyết được bằng phân tích alias/type thật (ngoài phạm vi
Tree-sitter query đơn giản ở Layer 2). Wrapper đặt tên kiểu camelCase/
PascalCase không dùng underscore (vd. `mpackMemcpy`) LÚC ĐÓ cũng vẫn bị bỏ
sót — đã vá tiếp ở bản cập nhật bên dưới (2026-08-19).

### Mở rộng bắt wrapper dạng camelCase/PascalCase — vá 2026-08-19

**Bối cảnh:** Bản vá 2026-08-18 ở trên (`"(^|_)(...)($|_)"`) chỉ bắt được
wrapper phân tách bằng underscore (`mpack_memcpy`). Wrapper đặt tên theo
camelCase/PascalCase — không dùng underscore, phân tách "hump" bằng cách
viết hoa chữ cái đầu mỗi từ (vd. `mpackMemcpy`, `safeStrCpy`,
`MemcpyWrapper`) — vẫn lọt qua Layer 2 hoàn toàn, cùng bản chất false
negative "không được quét tới" như gap đã vá hôm trước, chỉ khác quy ước
đặt tên.

**Cách đã vá:** Thêm 1 nhánh `#match?` thứ hai (nối bằng `|`) vào TẤT CẢ
pattern trong cả `rules/c/c_sinks.scm` và `rules/cpp/cpp_sinks.scm` (mọi
nhóm CWE, cả bản qualify `std::` lẫn không-qualify — trừ `delete`/`delete[]`
vì đó là node từ khoá, không phải lời gọi hàm theo tên định danh nên không
áp dụng match-theo-tên):
`"(^|[a-z0-9_])(?=[A-Z])(?i:...)($|[A-Z]|[^a-zA-Z0-9])"`. Ý nghĩa từng phần:
biên trái là start-of-string/chữ thường/số/`_` (KHÔNG phải chữ hoa — tránh
dính 2 chữ hoa liền kề kiểu viết tắt, vd. không match `XStrcpy`); ngay sau
biên trái phải là 1 chữ hoa (`(?=[A-Z])`, lookahead không tiêu thụ ký tự —
đúng nghĩa "chữ cái đầu viết hoa ngay sau ranh giới từ"); so khớp tên sink
KHÔNG phân biệt hoa/thường qua scoped group `(?i:...)` (nên `StrCpy` — viết
hoa cả 2 "hump" — vẫn khớp `strcpy`, không chỉ riêng dạng `Strcpy` hoa mỗi
chữ đầu); biên phải là end-of-string/chữ hoa tiếp theo (hump mới)/ký tự
không phải chữ-số. Token danh sách sink giữ nguyên, không cần viết thêm bản
viết hoa riêng.

Regex engine của tree-sitter `#match?` hỗ trợ lookahead và scoped
case-insensitive group `(?i:...)` — đã kiểm chứng thực nghiệm bằng chính
`tree_sitter` binding của dự án (Python `Query`/`QueryCursor` thật, không
chỉ đọc tài liệu) trước khi viết vào rule.

**Kết quả kiểm chứng:** Bắt được `mpackMemcpy`, `safeStrCpy`,
`MemcpyWrapper`, `wrapper_Strcpy` (mix underscore + camelCase). KHÔNG match
nhầm `mallocator`, `freetype_init`, `somestrcpycall` (toàn chữ thường,
không có điểm chuyển hoa nào để nhánh camelCase bắt, không có `_` để nhánh
snake_case bắt), `myStructCpy` (không chứa chuỗi con `strcpy` liền mạch —
`Struct` ≠ `Str`+`cpy`), hay `XStrcpy` (chữ hoa liền trước, không phải ranh
giới từ hợp lệ). Test hồi quy trong `tests/unit/test_parsers.py`
(`test_parse_file_detects_camelcase_wrapper_function_names`) và xác nhận
tổng số candidate quét trên `samples/` không giảm so với trước khi vá
(`tests/integration/test_pipeline.py`).

**Giới hạn còn lại (không giải quyết được bằng regex theo tên):** Wrapper
đặt tên **hoàn toàn không chứa** tên sink gốc như một thành phần dưới bất
kỳ dạng viết hoa/thường/phân tách nào (vd. `safeCopy` không chứa
`strcpy`/`memcpy` dưới bất kỳ dạng nào) vẫn sẽ bị bỏ sót — đây là giới hạn
cố hữu của cách tiếp cận match theo tên định danh, chỉ giải quyết được bằng
phân tích alias/type thật (ngoài phạm vi Tree-sitter query đơn giản ở
Layer 2).

## Quy trình cập nhật model
