// =============================================================================
// HMAC-SHA1 wrapper
//
// Implements HMAC(K, M) = SHA1((K xor opad) || SHA1((K xor ipad) || M)).
// key_in must already be zero padded/truncated to 64 bytes by software.
// msg_in carries the first 64 message bytes; msg_len is clamped to 64 bytes.
// =============================================================================
`timescale 1ns / 1ps

module hmac_wrapper (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [511:0] key_in,
    input  wire [511:0] msg_in,
    input  wire [7:0]   msg_len,
    output wire [159:0] hmac_out,
    output reg          done
);

    localparam S_IDLE       = 4'd0;
    localparam S_INNER_INIT = 4'd1;
    localparam S_INNER_PAD  = 4'd2;
    localparam S_INNER_MSG  = 4'd3;
    localparam S_INNER_MSG2 = 4'd4;
    localparam S_OUTER_INIT = 4'd5;
    localparam S_OUTER_PAD  = 4'd6;
    localparam S_OUTER_HASH = 4'd7;
    localparam S_DONE       = 4'd8;

    reg [3:0] state;

    reg          sha_init;
    reg          sha_start;
    reg  [511:0] sha_block;
    wire [159:0] sha_hash;
    wire         sha_done;

    sha1_core u_sha1 (
        .clk      (clk),
        .rst_n    (rst_n),
        .init     (sha_init),
        .start    (sha_start),
        .block_in (sha_block),
        .hash_out (sha_hash),
        .done     (sha_done)
    );

    wire [511:0] key_ipad;
    wire [511:0] key_opad;

    genvar i;
    generate
        for (i = 0; i < 64; i = i + 1) begin : pad_gen
            assign key_ipad[(63-i)*8 +: 8] = key_in[(63-i)*8 +: 8] ^ 8'h36;
            assign key_opad[(63-i)*8 +: 8] = key_in[(63-i)*8 +: 8] ^ 8'h5C;
        end
    endgenerate

    reg [159:0] inner_hash_save;
    wire [7:0] msg_len_eff = (msg_len > 8'd64) ? 8'd64 : msg_len;

    function [63:0] inner_bit_length;
        input [7:0] len;
        begin
            inner_bit_length = (64'd64 + {56'd0, len}) << 3;
        end
    endfunction

    function [511:0] build_inner_block1;
        input [511:0] msg;
        input [7:0]   len;
        integer b;
        reg [511:0] block;
        begin
            block = 512'd0;
            for (b = 0; b < 64; b = b + 1) begin
                if (b < len) begin
                    block[(63-b)*8 +: 8] = msg[(63-b)*8 +: 8];
                end else if ((b == len) && (len < 8'd64)) begin
                    block[(63-b)*8 +: 8] = 8'h80;
                end
            end

            if (len <= 8'd55) begin
                block[63:0] = inner_bit_length(len);
            end

            build_inner_block1 = block;
        end
    endfunction

    function [511:0] build_inner_block2;
        input [7:0] len;
        reg [511:0] block;
        begin
            block = 512'd0;
            if (len >= 8'd64) begin
                block[511:504] = 8'h80;
            end
            block[63:0] = inner_bit_length(len);
            build_inner_block2 = block;
        end
    endfunction

    function [511:0] build_outer_block;
        input [159:0] inner_hash;
        begin
            build_outer_block = {inner_hash, 8'h80, 280'd0, 64'd672};
        end
    endfunction

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= S_IDLE;
            done            <= 1'b0;
            sha_init        <= 1'b0;
            sha_start       <= 1'b0;
            sha_block       <= 512'd0;
            inner_hash_save <= 160'd0;
        end else begin
            sha_init  <= 1'b0;
            sha_start <= 1'b0;
            done      <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start) begin
                        sha_init <= 1'b1;
                        state    <= S_INNER_INIT;
                    end
                end

                S_INNER_INIT: begin
                    sha_block <= key_ipad;
                    sha_start <= 1'b1;
                    state     <= S_INNER_PAD;
                end

                S_INNER_PAD: begin
                    if (sha_done) begin
                        sha_block <= build_inner_block1(msg_in, msg_len_eff);
                        sha_start <= 1'b1;
                        state     <= S_INNER_MSG;
                    end
                end

                S_INNER_MSG: begin
                    if (sha_done) begin
                        if (msg_len_eff > 8'd55) begin
                            sha_block <= build_inner_block2(msg_len_eff);
                            sha_start <= 1'b1;
                            state     <= S_INNER_MSG2;
                        end else begin
                            inner_hash_save <= sha_hash;
                            sha_init        <= 1'b1;
                            state           <= S_OUTER_INIT;
                        end
                    end
                end

                S_INNER_MSG2: begin
                    if (sha_done) begin
                        inner_hash_save <= sha_hash;
                        sha_init        <= 1'b1;
                        state           <= S_OUTER_INIT;
                    end
                end

                S_OUTER_INIT: begin
                    sha_block <= key_opad;
                    sha_start <= 1'b1;
                    state     <= S_OUTER_PAD;
                end

                S_OUTER_PAD: begin
                    if (sha_done) begin
                        sha_block <= build_outer_block(inner_hash_save);
                        sha_start <= 1'b1;
                        state     <= S_OUTER_HASH;
                    end
                end

                S_OUTER_HASH: begin
                    if (sha_done) begin
                        done  <= 1'b1;
                        state <= S_DONE;
                    end
                end

                S_DONE: begin
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    assign hmac_out = sha_hash;

endmodule
