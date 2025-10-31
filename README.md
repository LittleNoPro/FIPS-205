# Stateless Hash-Based Digital Signature (FIPS 205)

## 1. Overview of the SLH-DSA Signature Scheme

**SLH-DSA** là một sơ đồ chữ ký dựa trên hàm băm phi trạng thái (stateless hash-based signature scheme) được xây dựng bằng cách sử dụng các sơ đồ chữ ký dựa trên hàm băm khác làm thành phần: **(1) few-time signature scheme, forest of random subsets - FORS, và (2) multi-time signature scheme, eXtended Merkle Signture Scheme - XMSS**. **XMSS** được xây dựng bằng cách sử dụng sơ đồ chữ ký dùng một lần dựa trên hàm băm **Winternitz One-Time Signature Plus (WOTS⁺)** làm thành phần.

Về mặt khái niệm, một cặp khóa **SLH-DSA** bao gồm một tập hợp rất lớn các cặp khóa **FORS**. Sơ đồ chữ ký dùng vài lần **FORS** cho phép mỗi cặp khóa có thể ký an toàn một lượng thông điệp nhỏ. Một chữ ký **SLH-DSA** được tạo ra bằng cách tính toán một giá trị băm của thông điệp, sử dụng một phần của giá trị băm kết quả để chọn ngẫu nhiên một khóa **FORS**, và ký phần còn lại của giá trị băm thông điệp bằng khóa đó. Một chữ ký **SLH-DSA** bao gồm chữ ký **FORS** và thông tin xác thực của khóa công khai **FORS**. Thông tin xác thực được tạo ra bằng các chữ ký **XMSS**.

**XMSS** là một sơ đồ chữ ký dùng nhiều lần được tạo ra bằng cách kết hợp các chữ ký dùng một lần **WOTS⁺** và các cây **Merkle**. Một khóa **XMSS** bao gồm $2^{h'}$ khóa **WOTS⁺** và có thể ký $2^{h'}$ thông điệp. Các khóa công khai **WOTS⁺** tạo thành một cây **Merkle**, và nút gốc **(root)** của cây chính là khóa công khai **XMSS**. Một chữ ký **XMSS** bao gồm một chữ ký **WOTS⁺** và một đường dẫn xác thực trong cây **Merkle** cho khóa công khai **WOTS⁺**.

Hình dưới đây mô phỏng lại quá trình tạo ra chữ ký cho một thông điệp. Các hình tam giác biểu diễn các cây **XMSS**, các hình vuông biểu diễn các khóa công khai **WOTS⁺** và các hình tròn biểu diễn các nút bên trong cây **XMSS**. Trong một cây **XMSS**, các hình vuông và hình tròn được tô đậm biểu diễn đường dẫn xác thực của khóa công khai **WOTS⁺** cần thiết để xác minh chữ ký.

![alt text](/images/1.png)

Thông tin xác thực cho một khóa công khai **FORS** là một chữ ký **hypertree**. Một **hypertree** là một cây của các cây **XMSS**. Cây này gồm $d$ lớp, trong đó lớp trên cùng là lớp thứ $d-1$ gồm một cây **XMSS** duy nhất, lớp kế tiếp có $2^{h'}$ cây **XMSS**,... và lớp thấp nhất (lớp $0$) có $2^{(d-1)h'}$ cây **XMSS**. Khóa công khai của mỗi cây **XMSS** ở các lớp $0 \rightarrow d-2$ được ký bởi một cây **XMSS** ở lớp cao hơn tiếp theo. Các khóa **XMSS** ở lớp $0$ có tổng cộng $2^{dh'} = 2^h$ khóa **WOTS⁺**, được sử dụng để ký $2^h$ khóa công khai **FORS** trong khóa công khai **SLH-DSA**. Chuỗi các chữ ký **XMSS** được sử dụng để xác thực một khóa công khai **FORS**, bắt đầu bằng khóa công khai **XMSS** ở lớp $d-1$, là một chữ ký **hypertree**. Một chữ ký **SLH-DSA** bao gồm chữ ký **FORS** cùng với chữ ký **hypertree** xác thực khóa công khai **FORS**.

Khóa công khai của **SLH-DSA** bao gồm $2$ thành phần có $n$-byte:
- **(1)** `PK.root`: khóa công khai (gốc của cây **XMSS**) ở lớp $d-1$.
- **(2)** `PK.seed`: được sử dụng để tạo sự tách biệt giữa các cặp khóa **SLH-DSA** khác nhau.

Khóa bí mật **SLH-DSA** bao gồm `SK.seed` ($n$-byte) được dùng để sinh ngẫu nhiên tất cả các giá trị bí mật cho các khóa **WOTS⁺** và **FORS**, cùng với một khóa $n$-byte `SK.prf` được sử dụng trong quá trình tạo băm ngẫu nhiên của thông điệp. Khóa bí mật **SLH-DSA** cũng bao gồm `PK.root` và `PK.seed`, vì chúng cần thiết trong cả quá trình tạo chữ ký và xác minh chữ ký.

## 2. Functions and Addressing

### 2.1 Hash Functions and Pseudorandom Functions

**SLH-DSA** được thực hiện bởi $6$ hàm $- PRF_{msg}, H_{msg}, PRF, T_\mathbb{l}, H, F -$ chúng đều được xây dựng sử dụng hàm **hash** hoặc [XOFs](https://csrc.nist.gov/glossary/term/extendable_output_function) với độ dài đầu ra cố định. Đầu vào và đầu ra của mỗi **function** đều là các chuỗi bytes. Ta định nghĩa $\mathbb{B} = \{0,...,255 \}$ là một tập hợp các bytes, $\mathbb{B}^n$ là tập hợp các chuỗi bytes mà mỗi chuỗi có chính xác $n$-bytes và $\mathbb{B}^*$ là một tập hợp các chuỗi bytes. Chi tiết về các hàm:
- $PRF_{msg}(SK.prf, opt\_rand, M) \ \ \  (\mathbb{B}^n \times \mathbb{B}^n \times \mathbb{B}^* \rightarrow \mathbb{B}^n)$: là hàm giả ngẫu nhiên (PRF) được sử dụng để tạo ra các giá trị ngẫu nhiên hóa $(R)$ cho việc băm ngẫu nhiên của thông điệp cần ký.
- $H_{msg}(R, PK.seed, PK.root, M) \ \ \  (\mathbb{B}^n \times \mathbb{B}^n \times \mathbb{B}^n \times \mathbb{B}^* \rightarrow \mathbb{B}^n)$: hàm này được sử dụng để tạo **digest** cho thông điệp cần ký.
- $PRF(PK.seed, SK.seed, ADRS) \ \ \  (\mathbb{B}^n \times \mathbb{B}^n \times \mathbb{B}^{32} \rightarrow \mathbb{B}^n)$: là một PRF được sử dụng để tạo các giá trị bí mật trong khóa riêng của **WOTS⁺** và **FORS**.
- $T_l(PK.seed, ADRS, M_l) \ \ \  (\mathbb{B}^n \times \mathbb{B}^{32} \times \mathbb{B}^{ln} \rightarrow \mathbb{B}^n)$: đây là một hàm **hash** ánh xạ một thông điệp $ln$-bytes thành một thông điệp $n$-bytes.
- $H(PK.seed, ADRS, M_2) \ \ \  (\mathbb{B}^n \times \mathbb{B}^{32} \times \mathbb{B}^{2n} \rightarrow \mathbb{B}^n)$: là một trường hợp đặc biệt của hàm $T_l$ khi nó nhận đầu vào là một thông điệp $2n$-bytes.
- $F(PK.seed, ADRS, M_1) \ \ \  (\mathbb{B}^n \times \mathbb{B}^{32} \times \mathbb{B}^n \rightarrow \mathbb{B}^n)$: là một hàm **hash** nhập vào chuỗi $n$-bytes và xử lý tạo thành một chuỗi $n$-bytes.













## References
[1] Stateless Hash-Based Digital Signature Standard. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf

[2] How do hash-based post-quantum digital signatures work? (Part 1) https://research.dorahacks.io/2022/10/26/hash-based-post-quantum-signatures-1/

[3] How do hash-based post-quantum digital signatures work? (Part 2) https://research.dorahacks.io/2022/12/16/hash-based-post-quantum-signatures-2/