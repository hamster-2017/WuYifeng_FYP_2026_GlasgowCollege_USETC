


























module axi_aes_wrapper #(
    parameter C_S_AXI_DATA_WIDTH = 32,
    parameter C_S_AXI_ADDR_WIDTH = 7
) (
    input  wire                                S_AXI_ACLK,
    input  wire                                S_AXI_ARESETN,
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]       S_AXI_AWADDR,
    input  wire [2:0]                          S_AXI_AWPROT,
    input  wire                                S_AXI_AWVALID,
    output reg                                 S_AXI_AWREADY,
    input  wire [C_S_AXI_DATA_WIDTH-1:0]       S_AXI_WDATA,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0]   S_AXI_WSTRB,
    input  wire                                S_AXI_WVALID,
    output reg                                 S_AXI_WREADY,
    output wire [1:0]                          S_AXI_BRESP,
    output reg                                 S_AXI_BVALID,
    input  wire                                S_AXI_BREADY,
    input  wire [C_S_AXI_ADDR_WIDTH-1:0]       S_AXI_ARADDR,
    input  wire [2:0]                          S_AXI_ARPROT,
    input  wire                                S_AXI_ARVALID,
    output reg                                 S_AXI_ARREADY,
    output reg  [C_S_AXI_DATA_WIDTH-1:0]       S_AXI_RDATA,
    output wire [1:0]                          S_AXI_RRESP,
    output reg                                 S_AXI_RVALID,
    input  wire                                S_AXI_RREADY
);

    assign S_AXI_BRESP = 2'b00;
    assign S_AXI_RRESP = 2'b00;

    reg [31:0] reg_key  [0:3];    
    reg [31:0] reg_iv   [0:3];    
    reg [31:0] reg_din  [0:3];    

    reg        ctrl_start;
    reg        ctrl_decrypt;
    reg        ctrl_key_load;
    reg        ctrl_iv_load;

    wire [127:0] aes_key_in  = {reg_key[0], reg_key[1], reg_key[2], reg_key[3]};
    wire [127:0] aes_iv_in   = {reg_iv[0],  reg_iv[1],  reg_iv[2],  reg_iv[3]};
    wire [127:0] aes_data_in = {reg_din[0], reg_din[1], reg_din[2], reg_din[3]};
    wire [127:0] aes_data_out;
    wire         aes_done;
    wire         aes_key_ready;

    reg status_done_latched;
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            status_done_latched <= 1'b0;
        end else begin
            if (ctrl_start) begin
                status_done_latched <= 1'b0; 
            end else if (aes_done) begin
                status_done_latched <= 1'b1; 
            end
        end
    end

    aes_top u_aes (
        .clk       (S_AXI_ACLK),
        .rst_n     (S_AXI_ARESETN),
        .start     (ctrl_start),
        .decrypt   (ctrl_decrypt),
        .key_load  (ctrl_key_load),
        .iv_load   (ctrl_iv_load),
        .key_in    (aes_key_in),
        .iv_in     (aes_iv_in),
        .data_in   (aes_data_in),
        .data_out  (aes_data_out),
        .key_ready (aes_key_ready),
        .done      (aes_done)
    );

    reg [C_S_AXI_ADDR_WIDTH-1:0] aw_addr_latched;
    reg aw_ready_done;

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_AWREADY  <= 1'b0;
            aw_addr_latched <= 0;
            aw_ready_done   <= 1'b0;
        end else begin
            if (S_AXI_AWVALID && !aw_ready_done) begin
                S_AXI_AWREADY  <= 1'b1;
                aw_addr_latched <= S_AXI_AWADDR;
                aw_ready_done   <= 1'b1;
            end else begin
                S_AXI_AWREADY <= 1'b0;
                if (S_AXI_BVALID && S_AXI_BREADY)
                    aw_ready_done <= 1'b0;
            end
        end
    end

    reg w_ready_done;

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_WREADY  <= 1'b0;
            w_ready_done  <= 1'b0;
            ctrl_start    <= 1'b0;
            ctrl_key_load <= 1'b0;
            ctrl_iv_load  <= 1'b0;
            ctrl_decrypt  <= 1'b0;
            reg_key[0] <= 32'd0; reg_key[1] <= 32'd0;
            reg_key[2] <= 32'd0; reg_key[3] <= 32'd0;
            reg_iv[0]  <= 32'd0; reg_iv[1]  <= 32'd0;
            reg_iv[2]  <= 32'd0; reg_iv[3]  <= 32'd0;
            reg_din[0] <= 32'd0; reg_din[1] <= 32'd0;
            reg_din[2] <= 32'd0; reg_din[3] <= 32'd0;
        end else begin
            ctrl_start    <= 1'b0;
            ctrl_key_load <= 1'b0;
            ctrl_iv_load  <= 1'b0;

            if (S_AXI_WVALID && !w_ready_done && aw_ready_done) begin
                S_AXI_WREADY <= 1'b1;
                w_ready_done <= 1'b1;

                case (aw_addr_latched[6:2])  
                    5'h00: begin 
                        ctrl_start    <= S_AXI_WDATA[0];
                        ctrl_decrypt  <= S_AXI_WDATA[1];
                        ctrl_key_load <= S_AXI_WDATA[2];
                        ctrl_iv_load  <= S_AXI_WDATA[3];
                    end
                    5'h04: reg_key[0]  <= S_AXI_WDATA; 
                    5'h05: reg_key[1]  <= S_AXI_WDATA;
                    5'h06: reg_key[2]  <= S_AXI_WDATA;
                    5'h07: reg_key[3]  <= S_AXI_WDATA;
                    5'h08: reg_iv[0]   <= S_AXI_WDATA;
                    5'h09: reg_iv[1]   <= S_AXI_WDATA;
                    5'h0A: reg_iv[2]   <= S_AXI_WDATA;
                    5'h0B: reg_iv[3]   <= S_AXI_WDATA;
                    5'h0C: reg_din[0]  <= S_AXI_WDATA;
                    5'h0D: reg_din[1]  <= S_AXI_WDATA;
                    5'h0E: reg_din[2]  <= S_AXI_WDATA;
                    5'h0F: reg_din[3]  <= S_AXI_WDATA;
                    default: ; 
                endcase
            end else begin
                S_AXI_WREADY <= 1'b0;
                if (S_AXI_BVALID && S_AXI_BREADY)
                    w_ready_done <= 1'b0;
            end
        end
    end

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_BVALID <= 1'b0;
        end else begin
            if (aw_ready_done && w_ready_done && !S_AXI_BVALID) begin
                S_AXI_BVALID <= 1'b1;
            end else if (S_AXI_BVALID && S_AXI_BREADY) begin
                S_AXI_BVALID <= 1'b0;
            end
        end
    end

    reg [C_S_AXI_ADDR_WIDTH-1:0] ar_addr_latched;

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_ARREADY   <= 1'b0;
            ar_addr_latched  <= 0;
        end else begin
            if (S_AXI_ARVALID && !S_AXI_ARREADY) begin
                S_AXI_ARREADY   <= 1'b1;
                ar_addr_latched  <= S_AXI_ARADDR;
            end else begin
                S_AXI_ARREADY <= 1'b0;
            end
        end
    end

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_RDATA  <= 32'd0;
            S_AXI_RVALID <= 1'b0;
        end else begin
            if (S_AXI_ARREADY) begin
                S_AXI_RVALID <= 1'b1;

                case (ar_addr_latched[6:2])
                    5'h01: 
                        S_AXI_RDATA <= {30'd0, aes_key_ready, status_done_latched};
                    5'h10: 
                        S_AXI_RDATA <= aes_data_out[127:96];
                    5'h11: 
                        S_AXI_RDATA <= aes_data_out[95:64];
                    5'h12: 
                        S_AXI_RDATA <= aes_data_out[63:32];
                    5'h13: 
                        S_AXI_RDATA <= aes_data_out[31:0];
                    default:
                        S_AXI_RDATA <= 32'hDEADBEEF;
                endcase
            end else if (S_AXI_RVALID && S_AXI_RREADY) begin
                S_AXI_RVALID <= 1'b0;
            end
        end
    end

endmodule
