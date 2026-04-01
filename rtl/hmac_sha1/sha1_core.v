












`timescale 1ns / 1ps

module sha1_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         init,          
    input  wire         start,         
    input  wire [511:0] block_in,      
    output wire [159:0] hash_out,      
    output reg          done           
);

    localparam [31:0] H0_INIT = 32'h67452301;
    localparam [31:0] H1_INIT = 32'hEFCDAB89;
    localparam [31:0] H2_INIT = 32'h98BADCFE;
    localparam [31:0] H3_INIT = 32'h10325476;
    localparam [31:0] H4_INIT = 32'hC3D2E1F0;

    function [31:0] sha1_k;
        input [6:0] t;
        if (t < 20)      sha1_k = 32'h5A827999;
        else if (t < 40) sha1_k = 32'h6ED9EBA1;
        else if (t < 60) sha1_k = 32'h8F1BBCDC;
        else              sha1_k = 32'hCA62C1D6;
    endfunction

    function [31:0] sha1_f;
        input [6:0] t;
        input [31:0] b, c, d;
        if (t < 20)      sha1_f = (b & c) | (~b & d);          
        else if (t < 40) sha1_f = b ^ c ^ d;                   
        else if (t < 60) sha1_f = (b & c) | (b & d) | (c & d); 
        else              sha1_f = b ^ c ^ d;                   
    endfunction

    function [31:0] rotl;
        input [31:0] x;
        input [4:0]  n;
        rotl = (x << n) | (x >> (32 - n));
    endfunction

    localparam S_IDLE    = 2'd0;
    localparam S_PREPARE = 2'd1;
    localparam S_COMPUTE = 2'd2;
    localparam S_FINAL   = 2'd3;

    reg [1:0]  state;
    reg [6:0]  round;              

    reg [31:0] w [0:15];

    reg [31:0] a, b, c, d, e;

    reg [31:0] h0, h1, h2, h3, h4;

    assign hash_out = {h0, h1, h2, h3, h4};

    wire [31:0] w_current;
    wire [31:0] w_new = rotl(w[(round)    & 4'hF] ^ 
                              w[(round-2) & 4'hF] ^  
                              w[(round-8) & 4'hF] ^  
                              w[(round)   & 4'hF], 5'd1);

    wire [3:0] idx_t3  = (round - 3)  & 4'hF;
    wire [3:0] idx_t8  = (round - 8)  & 4'hF;
    wire [3:0] idx_t14 = (round - 14) & 4'hF;
    wire [3:0] idx_t16 = (round)      & 4'hF;  

    wire [31:0] w_expanded = rotl(w[idx_t3] ^ w[idx_t8] ^ w[idx_t14] ^ w[idx_t16], 5'd1);

    assign w_current = (round < 16) ? w[round[3:0]] : w_expanded;

    wire [31:0] temp = rotl(a, 5'd5) + sha1_f(round, b, c, d) + e + sha1_k(round) + w_current;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= S_IDLE;
            round <= 7'd0;
            done  <= 1'b0;
            h0 <= H0_INIT; h1 <= H1_INIT; h2 <= H2_INIT; h3 <= H3_INIT; h4 <= H4_INIT;
            a <= 32'd0; b <= 32'd0; c <= 32'd0; d <= 32'd0; e <= 32'd0;
        end else begin
            done <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (init) begin
                        h0 <= H0_INIT; h1 <= H1_INIT;
                        h2 <= H2_INIT; h3 <= H3_INIT; h4 <= H4_INIT;
                    end else if (start) begin
                        w[0]  <= block_in[511:480]; w[1]  <= block_in[479:448];
                        w[2]  <= block_in[447:416]; w[3]  <= block_in[415:384];
                        w[4]  <= block_in[383:352]; w[5]  <= block_in[351:320];
                        w[6]  <= block_in[319:288]; w[7]  <= block_in[287:256];
                        w[8]  <= block_in[255:224]; w[9]  <= block_in[223:192];
                        w[10] <= block_in[191:160]; w[11] <= block_in[159:128];
                        w[12] <= block_in[127:96];  w[13] <= block_in[95:64];
                        w[14] <= block_in[63:32];   w[15] <= block_in[31:0];

                        a <= h0; b <= h1; c <= h2; d <= h3; e <= h4;
                        round <= 7'd0;
                        state <= S_COMPUTE;
                    end
                end

                S_COMPUTE: begin
                    e <= d;
                    d <= c;
                    c <= rotl(b, 5'd30);
                    b <= a;
                    a <= temp;

                    if (round >= 16) begin
                        w[round[3:0]] <= w_expanded;
                    end

                    if (round == 79) begin
                        state <= S_FINAL;
                    end
                    round <= round + 1;
                end

                S_FINAL: begin
                    h0 <= h0 + a;
                    h1 <= h1 + b;
                    h2 <= h2 + c;
                    h3 <= h3 + d;
                    h4 <= h4 + e;
                    done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
