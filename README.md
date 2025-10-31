# Stateless Hash-Based Digital Signature (FIPS 205)

## Overview of the SLH-DSA Signature Scheme

**SLH-DSA** là một sơ đồ chữ ký dựa trên hàm băm không trạng thái (stateless hash-based signature scheme) được xây dựng bằng cách sử dụng các sơ đồ chữ ký dựa trên hàm băm khác làm thành phần: **(1) few-time signature scheme, forest of random subsets - FORS, và (2) multi-time signature scheme, eXtended Merkle Signture Scheme - XMSS**. **XMSS** được xây dựng bằng cách sử dụng sơ đồ chữ ký dùng một lần dựa trên hàm băm **Winternitz One-Time Signature Plus (WOTS⁺)** làm thành phần.

Về mặt khái niệm, một cặp khóa **SLH-DSA** bao gồm một tập hợp rất lớn các cặp khóa **FORS**. Sơ đồ chữ ký dùng vài lần **FORS** cho phép mỗi cặp khóa có thể ký an toàn một lượng thông điệp nhỏ. Một chữ ký **SLH-DSA** được tạo ra bằng cách tính toán một giá trị băm của thông điệp, sử dụng một phần của giá trị băm kết quả để chọn ngẫu nhiên một khóa **FORS**, và ký phần còn lại của giá trị băm thông điệp bằng khóa đó. Một chữ ký **SLH-DSA** bao gồm chữ ký **FORS** và thông tin xác thực của khóa công khai **FORS**. Thông tin xác thực được tạo ra bằng các chữ ký **XMSS**.

