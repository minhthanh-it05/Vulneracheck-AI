# weights/

Thư mục này chứa artifact của model GraphCodeBERT (Layer 3 — verifier) dùng để
phân loại nhị phân an toàn/có lỗi cho các candidate sink do Layer 2 forward tới.

`model.onnx` được track qua **Git LFS** (xem `.gitattributes` ở root repo:
`*.onnx filter=lfs diff=lfs merge=lfs -text`) — không phải file bị `.gitignore`
loại trừ. Cần `git lfs pull` (hoặc clone với `git lfs` đã cài) để lấy được nội
dung thật của file thay vì chỉ con trỏ LFS.

## Các file thật đang có trong `weights/`

| File / thư mục | Mô tả |
|---|---|
| `model.onnx` | Model GraphCodeBERT (RoBERTa-based) đã fine-tune cho 3 ngôn ngữ C/C++/Java, export sang ONNX, **opset version 14**. Định dạng **FP32** — xem mục "INT8 quantization" bên dưới về lý do không dùng bản quantize. Đã chạy qua `onnxruntime.quantization.shape_inference.quant_pre_process` trước khi verify (bước preprocess chuẩn khuyến nghị của ONNX Runtime, không gây lỗi nên được giữ lại dù không dùng để quantize thành công). |
| `tokenizer/` | Thư mục tokenizer đầy đủ theo định dạng Hugging Face `transformers`, gồm 5 file: `tokenizer.json`, `tokenizer_config.json`, `vocab.json`, `merges.txt`, `special_tokens_map.json`. Nạp bằng `AutoTokenizer.from_pretrained("weights/tokenizer")`. |
| `threshold_config.json` | Cấu hình threshold + uncertain-zone đã calibrate, xem chi tiết bên dưới. |

### `threshold_config.json` — cấu trúc và ý nghĩa

```json
{
  "thresholds": {"c": 0.6, "cpp": 0.1, "java": 0.05},
  "uncertain_zones": {
    "c": [0.52, 0.68],
    "cpp": [0.02, 0.18],
    "java": [0.011, 0.089]
  }
}
```

- `thresholds`: **mỗi ngôn ngữ có một ngưỡng quyết định riêng**, không dùng chung một mốc 0.5. Xác suất `P(vulnerable)` do model trả về được so với threshold của đúng ngôn ngữ đó để ra label 0/1. Các threshold này đã được calibrate để đạt `target_recall = 0.92` trên tập dữ liệu đánh giá nội bộ, trong khi giới hạn tỷ lệ finding cần review thủ công ở mức `max_review_pct = 0.25`.
- `uncertain_zones`: khoảng xác suất mà model không đủ tin cậy để tự động kết luận — nếu `P(vulnerable)` rơi vào khoảng này, `ONNXVerifier` trả về `status="UNCERTAIN_NEEDS_REVIEW"` thay vì `OK`, tức là finding cần con người xem lại thay vì tin tuyệt đối vào label tự động.

### INT8 quantization

INT8 quantization đã được thử nhưng bị loại bỏ do sai số (accuracy degradation)
quá lớn trên attention layer của kiến trúc RoBERTa-based — không đạt độ chính
xác chấp nhận được để dùng trong production. Vì vậy `model.onnx` hiện tại là
bản **FP32**, không phải bản quantized. Chi tiết định lượng (nếu có) xem
`docs/model_card.md`.

## Phạm vi hỗ trợ

Model **chỉ hỗ trợ 3 ngôn ngữ: C, C++, Java** (`SUPPORTED_ML_LANGUAGES` trong
`src/vulneracheck/verifier/__init__.py`). Với ngôn ngữ khác, `ONNXVerifier.predict()`
/ `predict_batch()` **không raise lỗi** — trả về `VerifierResult(ml_verified=False,
confidence=None, label=None, status="ML_NOT_SUPPORTED")` để pipeline có thể tiếp
tục xử lý các candidate còn lại một cách bình thường.

## Known Limitations

- **Chưa test trên PR/repo thật** — mới chỉ test trên tập test nội bộ (sample nhỏ
  tự viết trong `samples/`), chưa chạy end-to-end trên một pull request hay
  repository thực tế nào.
- **Java có độ phân tách (separation) kém hơn C/C++** — suy luận gián tiếp từ
  việc threshold của Java phải hạ rất sâu (0.05, so với 0.6 của C) mới đạt đủ
  `target_recall = 0.92`, cho thấy phân bố xác suất của model trên Java lệch xa
  mốc tự nhiên 0.5 hơn C/C++.
- **Nguy cơ distribution shift** giữa dữ liệu train (function/sample đã được
  curate) và dữ liệu Layer 2 sẽ forward trong thực tế (snippet cắt quanh sink,
  ngữ cảnh cụt hơn, độ dài/style khác) — chưa có cách đo trực tiếp rủi ro này
  cho tới khi chạy trên dữ liệu thật.
- **Số liệu benchmark chi tiết (accuracy/precision/recall/F1): TBD, xem
  `docs/model_card.md`** — tài liệu đó hiện chưa có nội dung, chỉ có
  `threshold_config.json` làm nguồn calibration thật duy nhất trong repo tính
  đến thời điểm này.

## Quy trình lấy model từ Google Colab

1. Huấn luyện / fine-tune GraphCodeBERT trên Google Colab (GPU runtime).
2. Export sang ONNX (opset 14).
3. Chạy `onnxruntime.quantization.shape_inference.quant_pre_process` để preprocess
   model trước khi verify.
4. (Đã thử, không dùng) Quantize INT8 — bị loại vì sai số quá lớn, xem mục
   "INT8 quantization" ở trên. Sản phẩm cuối cùng dùng thẳng bản FP32 sau bước 3.
5. Tải về máy local và đặt vào `weights/` đúng layout hiện tại:
   ```
   weights/
   ├── README.md
   ├── model.onnx
   ├── threshold_config.json
   └── tokenizer/
       ├── tokenizer.json
       ├── tokenizer_config.json
       ├── vocab.json
       ├── merges.txt
       └── special_tokens_map.json
   ```

## Lưu ý

- `src/vulneracheck/verifier/__init__.py` tự động trỏ tới `weights/model.onnx`,
  `weights/tokenizer`, `weights/threshold_config.json` (`DEFAULT_MODEL_PATH`,
  `DEFAULT_TOKENIZER_PATH`, `DEFAULT_THRESHOLD_CONFIG_PATH`). Nếu đổi vị trí/tên
  file, cập nhật các hằng số này.
