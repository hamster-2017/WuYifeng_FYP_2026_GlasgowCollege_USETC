



















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

    localparam S_IDLE        = 3'd0;
    localparam S_INNER_INIT  = 3'd1;
    localparam S_INNER_PAD   = 3'd2;
    localparam S_INNER_MSG   = 3'd3;
    localparam S_OUTER_INIT  = 3'd4;
    localparam S_OUTER_PAD   = 3'd5;
    localparam S_OUTER_HASH  = 3'd6;
    localparam S_DONE        = 3'd7;

    reg [2:0] state;

    reg          sha_init;
    reg          sha_start;
    reg  [511:0] sha_block;
    wire [159:0] sha_hash;
    wire         sha_done;

    sha1_core u_sha1 (
        .clk       (clk),
        .rst_n     (rst_n),
        .init      (sha_init),
        .start     (sha_start),
        .block_in  (sha_block),
        .hash_out  (sha_hash),
        .done      (sha_done)
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


    reg [511:0] msg_padded;
    reg [159:0] inner_hash_save;

    wire [63:0] inner_total_bits = {48'd0, 8'd64 + msg_len, 3'b000};  

    wire [511:0] outer_msg_padded = {
        inner_hash_save,   
        8'h80,             
        216'd0,            
        64'd672            
    };
    wire [511:0] outer_block2 = {inner_hash_save, 8'h80, 280'd0, 64'd672};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            done      <= 1'b0;
            sha_init  <= 1'b0;
            sha_start <= 1'b0;
            sha_block <= 512'd0;
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
                        begin : build_inner_msg
                            integer j;
                            reg [511:0] padded;
                            padded = 512'd0;
                            padded = msg_in;
                            padded[(63 - msg_len) * 8 +: 8] = 8'h80;
                            padded[63:0] = {48'd0, (16'd64 + {8'd0, msg_len})} << 3;
                            msg_padded = padded;
                        end

                        sha_block <= msg_padded;
                        sha_start <= 1'b1;
                        state     <= S_INNER_MSG;
                    end
                end

                S_INNER_MSG: begin
                    if (sha_done) begin
                        inner_hash_save <= sha_hash;
                        sha_init <= 1'b1;
                        state    <= S_OUTER_INIT;
                    end
                end

                S_OUTER_INIT: begin
                    sha_block <= key_opad;
                    sha_start <= 1'b1;
                    state     <= S_OUTER_PAD;
                end

                S_OUTER_PAD: begin
                    if (sha_done) begin
                        sha_block <= outer_block2;
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
