# weights/

Thư mục này chứa các artifact của model AI dùng để xác minh (verify) các finding
do rule engine phát hiện. **Không commit các file model vào git** (đã bị loại trừ
trong `.gitignore`).

## Các file cần đặt tại đây

| File                    | Mô tả                                                              |
|--------------------------|---------------------------------------------------------------------|
| `model_quantized.onnx`  | Model đã được huấn luyện, export và quantize (INT8) sang ONNX      |
| `tokenizer.json`        | Tokenizer tương ứng với model (Hugging Face `tokenizers` format)   |

## Quy trình lấy model từ Google Colab

1. Huấn luyện / fine-tune model trên Google Colab (GPU runtime).
2. Export model sang ONNX:
   ```python
   from transformers.onnx import export
   # hoặc torch.onnx.export(...) tuỳ pipeline huấn luyện
   ```
3. Quantize model để giảm kích thước và tăng tốc inference trên edge:
   ```python
   from onnxruntime.quantization import quantize_dynamic, QuantType

   quantize_dynamic(
       model_input="model.onnx",
       model_output="model_quantized.onnx",
       weight_type=QuantType.QInt8,
   )
   ```
4. Tải hai file sau về máy local:
   - `model_quantized.onnx`
   - `tokenizer.json`
5. Đặt cả hai file trực tiếp vào thư mục `weights/` này (cùng cấp với `README.md`):
   ```
   weights/
   ├── README.md
   ├── model_quantized.onnx
   └── tokenizer.json
   ```

## Lưu ý

- `src/verifier/` sẽ tự động tìm model tại đường dẫn `weights/model_quantized.onnx`
  khi khởi tạo `ONNXVerifier`.
- Nếu thay đổi vị trí hoặc tên file, cập nhật cấu hình tương ứng trong `src/verifier/`.
