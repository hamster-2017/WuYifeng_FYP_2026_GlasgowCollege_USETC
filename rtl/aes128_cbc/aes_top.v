









module aes_top (
    input  wire         clk,
    input  wire         rst_n,

    input  wire         start,         
    input  wire         decrypt,       
    input  wire         key_load,      
    input  wire         iv_load,       

    input  wire [127:0] key_in,        
    input  wire [127:0] iv_in,         
    input  wire [127:0] data_in,       
    output wire [127:0] data_out,      

    output wire         key_ready,     
    output wire         done           
);

    wire [127:0] round_keys [0:10];

    wire         cbc_aes_start;
    wire         cbc_aes_decrypt;
    wire [127:0] cbc_aes_data_in;
    wire [127:0] aes_core_data_out;
    wire         aes_core_done;

    aes_key_expand u_key_expand (
        .clk          (clk),
        .rst_n        (rst_n),
        .key_load     (key_load),
        .key_in       (key_in),
        .key_ready    (key_ready),
        .round_key_0  (round_keys[0]),
        .round_key_1  (round_keys[1]),
        .round_key_2  (round_keys[2]),
        .round_key_3  (round_keys[3]),
        .round_key_4  (round_keys[4]),
        .round_key_5  (round_keys[5]),
        .round_key_6  (round_keys[6]),
        .round_key_7  (round_keys[7]),
        .round_key_8  (round_keys[8]),
        .round_key_9  (round_keys[9]),
        .round_key_10 (round_keys[10])
    );

    aes_core u_aes_core (
        .clk          (clk),
        .rst_n        (rst_n),
        .start        (cbc_aes_start),
        .decrypt      (cbc_aes_decrypt),
        .data_in      (cbc_aes_data_in),
        .round_key_0  (round_keys[0]),
        .round_key_1  (round_keys[1]),
        .round_key_2  (round_keys[2]),
        .round_key_3  (round_keys[3]),
        .round_key_4  (round_keys[4]),
        .round_key_5  (round_keys[5]),
        .round_key_6  (round_keys[6]),
        .round_key_7  (round_keys[7]),
        .round_key_8  (round_keys[8]),
        .round_key_9  (round_keys[9]),
        .round_key_10 (round_keys[10]),
        .data_out     (aes_core_data_out),
        .done         (aes_core_done)
    );

    cbc_mode u_cbc (
        .clk          (clk),
        .rst_n        (rst_n),
        .start        (start),
        .decrypt      (decrypt),
        .iv_load      (iv_load),
        .iv_in        (iv_in),
        .data_in      (data_in),
        .data_out     (data_out),
        .done         (done),
        .aes_start    (cbc_aes_start),
        .aes_decrypt  (cbc_aes_decrypt),
        .aes_data_in  (cbc_aes_data_in),
        .aes_data_out (aes_core_data_out),
        .aes_done     (aes_core_done)
    );

endmodule
