


module cbc_mode (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,         
    input  wire         decrypt,       
    input  wire         iv_load,       
    input  wire [127:0] iv_in,         
    input  wire [127:0] data_in,       
    output wire [127:0] data_out,      
    output wire         done,          

    output reg          aes_start,
    output reg          aes_decrypt,
    output reg  [127:0] aes_data_in,
    input  wire [127:0] aes_data_out,
    input  wire         aes_done
);

    localparam IDLE    = 2'd0;
    localparam WAIT    = 2'd1;
    localparam OUTPUT  = 2'd2;

    reg [1:0]   state;
    reg [127:0] chain_val;         
    reg [127:0] cipher_in_save;    
    reg [127:0] output_latch;      
    reg         is_decrypt;

    assign done     = (state == OUTPUT);
    assign data_out = output_latch;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state          <= IDLE;
            chain_val      <= 128'd0;
            cipher_in_save <= 128'd0;
            output_latch   <= 128'd0;
            aes_start      <= 1'b0;
            aes_decrypt    <= 1'b0;
            aes_data_in    <= 128'd0;
            is_decrypt     <= 1'b0;
        end else begin
            aes_start <= 1'b0;

            if (iv_load) begin
                chain_val <= iv_in;
            end

            case (state)
                IDLE: begin
                    if (start) begin
                        is_decrypt <= decrypt;
                        if (decrypt) begin
                            aes_data_in    <= data_in;
                            cipher_in_save <= data_in;
                        end else begin
                            aes_data_in <= data_in ^ chain_val;
                        end
                        aes_decrypt <= decrypt;
                        aes_start   <= 1'b1;
                        state       <= WAIT;
                    end
                end

                WAIT: begin
                    if (aes_done) begin
                        if (is_decrypt) begin
                            output_latch <= aes_data_out ^ chain_val;
                            chain_val    <= cipher_in_save;
                        end else begin
                            output_latch <= aes_data_out;
                            chain_val    <= aes_data_out;
                        end
                        state <= OUTPUT;
                    end
                end

                OUTPUT: begin
                    state <= IDLE;
                end

                default: state <= IDLE;
            endcase
        end
    end

endmodule
