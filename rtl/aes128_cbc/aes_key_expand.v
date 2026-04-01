






module aes_key_expand (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         key_load,      
    input  wire [127:0] key_in,        
    output wire         key_ready,     
    output wire [127:0] round_key_0,
    output wire [127:0] round_key_1,
    output wire [127:0] round_key_2,
    output wire [127:0] round_key_3,
    output wire [127:0] round_key_4,
    output wire [127:0] round_key_5,
    output wire [127:0] round_key_6,
    output wire [127:0] round_key_7,
    output wire [127:0] round_key_8,
    output wire [127:0] round_key_9,
    output wire [127:0] round_key_10
);

    reg [127:0] rk [0:10];
    reg [3:0]   expand_cnt;   
    reg         expanding;    
    reg         done;

    assign key_ready    = done;
    assign round_key_0  = rk[0];
    assign round_key_1  = rk[1];
    assign round_key_2  = rk[2];
    assign round_key_3  = rk[3];
    assign round_key_4  = rk[4];
    assign round_key_5  = rk[5];
    assign round_key_6  = rk[6];
    assign round_key_7  = rk[7];
    assign round_key_8  = rk[8];
    assign round_key_9  = rk[9];
    assign round_key_10 = rk[10];

    function [7:0] rcon;
        input [3:0] round;
        case (round)
            4'd1:  rcon = 8'h01;
            4'd2:  rcon = 8'h02;
            4'd3:  rcon = 8'h04;
            4'd4:  rcon = 8'h08;
            4'd5:  rcon = 8'h10;
            4'd6:  rcon = 8'h20;
            4'd7:  rcon = 8'h40;
            4'd8:  rcon = 8'h80;
            4'd9:  rcon = 8'h1b;
            4'd10: rcon = 8'h36;
            default: rcon = 8'h00;
        endcase
    endfunction

    wire [31:0] prev_last_word;
    wire [7:0]  sub_b0, sub_b1, sub_b2, sub_b3;
    wire [31:0] sub_word;
    wire [31:0] rot_sub_word;

    assign prev_last_word = rk[expand_cnt - 1][31:0];

    wire [31:0] rot_word = {prev_last_word[23:0], prev_last_word[31:24]};

    aes_sbox sb0 (.data_in(rot_word[31:24]), .decrypt(1'b0), .data_out(sub_b0));
    aes_sbox sb1 (.data_in(rot_word[23:16]), .decrypt(1'b0), .data_out(sub_b1));
    aes_sbox sb2 (.data_in(rot_word[15:8]),  .decrypt(1'b0), .data_out(sub_b2));
    aes_sbox sb3 (.data_in(rot_word[7:0]),   .decrypt(1'b0), .data_out(sub_b3));

    assign sub_word = {sub_b0, sub_b1, sub_b2, sub_b3};

    assign rot_sub_word = sub_word ^ {rcon(expand_cnt), 24'h000000};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            expand_cnt <= 4'd0;
            expanding  <= 1'b0;
            done       <= 1'b0;
        end else if (key_load) begin
            rk[0]      <= key_in;
            expand_cnt <= 4'd1;
            expanding  <= 1'b1;
            done       <= 1'b0;
        end else if (expanding) begin
            rk[expand_cnt][127:96] <= rk[expand_cnt-1][127:96] ^ rot_sub_word;
            rk[expand_cnt][95:64]  <= rk[expand_cnt-1][95:64]  ^ (rk[expand_cnt-1][127:96] ^ rot_sub_word);
            rk[expand_cnt][63:32]  <= rk[expand_cnt-1][63:32]  ^ rk[expand_cnt-1][95:64] ^ (rk[expand_cnt-1][127:96] ^ rot_sub_word);
            rk[expand_cnt][31:0]   <= rk[expand_cnt-1][31:0]   ^ rk[expand_cnt-1][63:32] ^ rk[expand_cnt-1][95:64] ^ (rk[expand_cnt-1][127:96] ^ rot_sub_word);

            if (expand_cnt == 4'd10) begin
                expanding <= 1'b0;
                done      <= 1'b1;
            end
            expand_cnt <= expand_cnt + 1;
        end
    end

endmodule
