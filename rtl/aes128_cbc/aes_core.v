








module aes_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,        
    input  wire         decrypt,      
    input  wire [127:0] data_in,      
    input  wire [127:0] round_key_0,
    input  wire [127:0] round_key_1,
    input  wire [127:0] round_key_2,
    input  wire [127:0] round_key_3,
    input  wire [127:0] round_key_4,
    input  wire [127:0] round_key_5,
    input  wire [127:0] round_key_6,
    input  wire [127:0] round_key_7,
    input  wire [127:0] round_key_8,
    input  wire [127:0] round_key_9,
    input  wire [127:0] round_key_10,
    output reg  [127:0] data_out,     
    output reg          done          
);

    localparam IDLE      = 2'd0;
    localparam ROUNDS    = 2'd2;
    localparam FINISH    = 2'd3;

    reg [1:0]   state;
    reg [3:0]   round_cnt;     
    reg [127:0] state_matrix;  

    reg [127:0] current_rk;
    always @(*) begin
        if (decrypt) begin
            case ((state == IDLE) ? 4'd0 : round_cnt)
                4'd0:  current_rk = round_key_10;
                4'd1:  current_rk = round_key_9;
                4'd2:  current_rk = round_key_8;
                4'd3:  current_rk = round_key_7;
                4'd4:  current_rk = round_key_6;
                4'd5:  current_rk = round_key_5;
                4'd6:  current_rk = round_key_4;
                4'd7:  current_rk = round_key_3;
                4'd8:  current_rk = round_key_2;
                4'd9:  current_rk = round_key_1;
                4'd10: current_rk = round_key_0;
                default: current_rk = 128'd0;
            endcase
        end else begin
            case ((state == IDLE) ? 4'd0 : round_cnt)
                4'd0:  current_rk = round_key_0;
                4'd1:  current_rk = round_key_1;
                4'd2:  current_rk = round_key_2;
                4'd3:  current_rk = round_key_3;
                4'd4:  current_rk = round_key_4;
                4'd5:  current_rk = round_key_5;
                4'd6:  current_rk = round_key_6;
                4'd7:  current_rk = round_key_7;
                4'd8:  current_rk = round_key_8;
                4'd9:  current_rk = round_key_9;
                4'd10: current_rk = round_key_10;
                default: current_rk = 128'd0;
            endcase
        end
    end

    wire [7:0] enc_sb_in  [0:15];
    wire [7:0] enc_sb_out [0:15];
    genvar i_enc;
    generate
        for (i_enc = 0; i_enc < 16; i_enc = i_enc + 1) begin : enc_sbox_gen
            aes_sbox u_sbox_enc (
                .data_in  (enc_sb_in[i_enc]),
                .decrypt  (1'b0),
                .data_out (enc_sb_out[i_enc])
            );
        end
    endgenerate

    assign enc_sb_in[0]  = state_matrix[127:120];
    assign enc_sb_in[1]  = state_matrix[119:112];
    assign enc_sb_in[2]  = state_matrix[111:104];
    assign enc_sb_in[3]  = state_matrix[103:96];
    assign enc_sb_in[4]  = state_matrix[95:88];
    assign enc_sb_in[5]  = state_matrix[87:80];
    assign enc_sb_in[6]  = state_matrix[79:72];
    assign enc_sb_in[7]  = state_matrix[71:64];
    assign enc_sb_in[8]  = state_matrix[63:56];
    assign enc_sb_in[9]  = state_matrix[55:48];
    assign enc_sb_in[10] = state_matrix[47:40];
    assign enc_sb_in[11] = state_matrix[39:32];
    assign enc_sb_in[12] = state_matrix[31:24];
    assign enc_sb_in[13] = state_matrix[23:16];
    assign enc_sb_in[14] = state_matrix[15:8];
    assign enc_sb_in[15] = state_matrix[7:0];

    wire [127:0] enc_after_sub = {
        enc_sb_out[0], enc_sb_out[1], enc_sb_out[2], enc_sb_out[3],
        enc_sb_out[4], enc_sb_out[5], enc_sb_out[6], enc_sb_out[7],
        enc_sb_out[8], enc_sb_out[9], enc_sb_out[10], enc_sb_out[11],
        enc_sb_out[12], enc_sb_out[13], enc_sb_out[14], enc_sb_out[15]
    };

    wire [7:0] e_s[0:15];
    assign {e_s[0],e_s[1],e_s[2],e_s[3], e_s[4],e_s[5],e_s[6],e_s[7], 
            e_s[8],e_s[9],e_s[10],e_s[11], e_s[12],e_s[13],e_s[14],e_s[15]} = enc_after_sub;
    wire [127:0] enc_after_shift = {
        e_s[0],  e_s[5],  e_s[10], e_s[15],   
        e_s[4],  e_s[9],  e_s[14], e_s[3],    
        e_s[8],  e_s[13], e_s[2],  e_s[7],    
        e_s[12], e_s[1],  e_s[6],  e_s[11]    
    };

    wire [127:0] enc_after_mix = {
        mix_column(enc_after_shift[127:96]),
        mix_column(enc_after_shift[95:64]),
        mix_column(enc_after_shift[63:32]),
        mix_column(enc_after_shift[31:0])
    };

    wire [127:0] enc_round_result = enc_after_mix ^ current_rk;
    wire [127:0] enc_final_result = enc_after_shift ^ current_rk;


    wire [7:0] d_s[0:15];
    assign {d_s[0],d_s[1],d_s[2],d_s[3], d_s[4],d_s[5],d_s[6],d_s[7], 
            d_s[8],d_s[9],d_s[10],d_s[11], d_s[12],d_s[13],d_s[14],d_s[15]} = state_matrix;

    wire [127:0] dec_after_shift = {
        d_s[0],  d_s[13], d_s[10], d_s[7],    
        d_s[4],  d_s[1],  d_s[14], d_s[11],   
        d_s[8],  d_s[5],  d_s[2],  d_s[15],   
        d_s[12], d_s[9],  d_s[6],  d_s[3]     
    };

    wire [7:0] dec_sb_in  [0:15];
    wire [7:0] dec_sb_out [0:15];
    genvar i_dec;
    generate
        for (i_dec = 0; i_dec < 16; i_dec = i_dec + 1) begin : dec_sbox_gen
            aes_sbox u_sbox_dec (
                .data_in  (dec_sb_in[i_dec]),
                .decrypt  (1'b1),
                .data_out (dec_sb_out[i_dec])
            );
        end
    endgenerate

    assign dec_sb_in[0]  = dec_after_shift[127:120];
    assign dec_sb_in[1]  = dec_after_shift[119:112];
    assign dec_sb_in[2]  = dec_after_shift[111:104];
    assign dec_sb_in[3]  = dec_after_shift[103:96];
    assign dec_sb_in[4]  = dec_after_shift[95:88];
    assign dec_sb_in[5]  = dec_after_shift[87:80];
    assign dec_sb_in[6]  = dec_after_shift[79:72];
    assign dec_sb_in[7]  = dec_after_shift[71:64];
    assign dec_sb_in[8]  = dec_after_shift[63:56];
    assign dec_sb_in[9]  = dec_after_shift[55:48];
    assign dec_sb_in[10] = dec_after_shift[47:40];
    assign dec_sb_in[11] = dec_after_shift[39:32];
    assign dec_sb_in[12] = dec_after_shift[31:24];
    assign dec_sb_in[13] = dec_after_shift[23:16];
    assign dec_sb_in[14] = dec_after_shift[15:8];
    assign dec_sb_in[15] = dec_after_shift[7:0];

    wire [127:0] dec_after_sub = {
        dec_sb_out[0], dec_sb_out[1], dec_sb_out[2], dec_sb_out[3],
        dec_sb_out[4], dec_sb_out[5], dec_sb_out[6], dec_sb_out[7],
        dec_sb_out[8], dec_sb_out[9], dec_sb_out[10], dec_sb_out[11],
        dec_sb_out[12], dec_sb_out[13], dec_sb_out[14], dec_sb_out[15]
    };

    wire [127:0] dec_after_add_rk = dec_after_sub ^ current_rk;

    wire [127:0] dec_round_result = {
        inv_mix_column(dec_after_add_rk[127:96]),
        inv_mix_column(dec_after_add_rk[95:64]),
        inv_mix_column(dec_after_add_rk[63:32]),
        inv_mix_column(dec_after_add_rk[31:0])
    };

    wire [127:0] dec_final_result = dec_after_add_rk;


    function [7:0] gf_mul2;
        input [7:0] x;
        gf_mul2 = {x[6:0], 1'b0} ^ (x[7] ? 8'h1b : 8'h00);
    endfunction

    function [7:0] gf_mul3;
        input [7:0] x;
        gf_mul3 = gf_mul2(x) ^ x;
    endfunction

    function [7:0] gf_mul9;
        input [7:0] x;
        gf_mul9 = gf_mul2(gf_mul2(gf_mul2(x))) ^ x;
    endfunction

    function [7:0] gf_mul11;
        input [7:0] x;
        gf_mul11 = gf_mul2(gf_mul2(gf_mul2(x))) ^ gf_mul2(x) ^ x; 
    endfunction

    function [7:0] gf_mul13;
        input [7:0] x;
        gf_mul13 = gf_mul2(gf_mul2(gf_mul2(x) ^ x)) ^ x;
    endfunction

    function [7:0] gf_mul14;
        input [7:0] x;
        gf_mul14 = gf_mul2(gf_mul2(gf_mul2(x) ^ x) ^ x);
    endfunction

    function [31:0] mix_column;
        input [31:0] col;
        reg [7:0] b0, b1, b2, b3;
        reg [7:0] r0, r1, r2, r3;
        begin
            b0 = col[31:24]; b1 = col[23:16]; b2 = col[15:8]; b3 = col[7:0];
            r0 = gf_mul2(b0) ^ gf_mul3(b1) ^ b2 ^ b3;
            r1 = b0 ^ gf_mul2(b1) ^ gf_mul3(b2) ^ b3;
            r2 = b0 ^ b1 ^ gf_mul2(b2) ^ gf_mul3(b3);
            r3 = gf_mul3(b0) ^ b1 ^ b2 ^ gf_mul2(b3);
            mix_column = {r0, r1, r2, r3};
        end
    endfunction

    function [31:0] inv_mix_column;
        input [31:0] col;
        reg [7:0] b0, b1, b2, b3;
        reg [7:0] r0, r1, r2, r3;
        begin
            b0 = col[31:24]; b1 = col[23:16]; b2 = col[15:8]; b3 = col[7:0];
            r0 = gf_mul14(b0) ^ gf_mul11(b1) ^ gf_mul13(b2) ^ gf_mul9(b3);
            r1 = gf_mul9(b0)  ^ gf_mul14(b1) ^ gf_mul11(b2) ^ gf_mul13(b3);
            r2 = gf_mul13(b0) ^ gf_mul9(b1)  ^ gf_mul14(b2) ^ gf_mul11(b3);
            r3 = gf_mul11(b0) ^ gf_mul13(b1) ^ gf_mul9(b2)  ^ gf_mul14(b3);
            inv_mix_column = {r0, r1, r2, r3};
        end
    endfunction


    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= IDLE;
            round_cnt    <= 4'd0;
            state_matrix <= 128'd0;
            data_out     <= 128'd0;
            done         <= 1'b0;
        end else begin
            case (state)
                IDLE: begin
                    done <= 1'b0;
                    if (start) begin
                        round_cnt    <= 4'd0;
                        state_matrix <= data_in ^ current_rk;
                        state        <= ROUNDS;
                        round_cnt    <= 4'd1;
                    end
                end

                ROUNDS: begin
                    if (round_cnt == 4'd10) begin
                        state_matrix <= decrypt ? dec_final_result : enc_final_result;
                        state        <= FINISH;
                    end else begin
                        state_matrix <= decrypt ? dec_round_result : enc_round_result;
                        round_cnt    <= round_cnt + 1;
                    end
                end

                FINISH: begin
                    data_out <= state_matrix;
                    done     <= 1'b1;
                    state    <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
