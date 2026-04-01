













`timescale 1ns / 1ps

module axi_hmac_wrapper #(
    parameter C_S_AXI_DATA_WIDTH = 32,
    parameter C_S_AXI_ADDR_WIDTH = 8
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

    reg [31:0] reg_key [0:15];   
    reg [31:0] reg_msg [0:15];   
    reg [7:0]  reg_msg_len;      
    reg        ctrl_start;

    wire [511:0] hmac_key;
    wire [511:0] hmac_msg;
    wire [159:0] hmac_out;
    wire         hmac_done;

    genvar gi;
    generate
        for (gi = 0; gi < 16; gi = gi + 1) begin : key_msg_concat
            assign hmac_key[(15-gi)*32 +: 32] = reg_key[gi];
            assign hmac_msg[(15-gi)*32 +: 32] = reg_msg[gi];
        end
    endgenerate

    hmac_wrapper u_hmac (
        .clk      (S_AXI_ACLK),
        .rst_n    (S_AXI_ARESETN),
        .start    (ctrl_start),
        .key_in   (hmac_key),
        .msg_in   (hmac_msg),
        .msg_len  (reg_msg_len),
        .hmac_out (hmac_out),
        .done     (hmac_done)
    );

    reg status_done_latched;
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            status_done_latched <= 1'b0;
        end else begin
            if (ctrl_start) begin
                status_done_latched <= 1'b0; 
            end else if (hmac_done) begin
                status_done_latched <= 1'b1; 
            end
        end
    end

    reg [C_S_AXI_ADDR_WIDTH-1:0] aw_addr;
    reg aw_done, w_done;

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_AWREADY <= 1'b0;
            aw_addr       <= 0;
            aw_done       <= 1'b0;
        end else begin
            if (S_AXI_AWVALID && !aw_done) begin
                S_AXI_AWREADY <= 1'b1;
                aw_addr       <= S_AXI_AWADDR;
                aw_done       <= 1'b1;
            end else begin
                S_AXI_AWREADY <= 1'b0;
                if (S_AXI_BVALID && S_AXI_BREADY) aw_done <= 1'b0;
            end
        end
    end

    integer idx;
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_WREADY <= 1'b0;
            w_done       <= 1'b0;
            ctrl_start   <= 1'b0;
            reg_msg_len  <= 8'd0;
            for (idx = 0; idx < 16; idx = idx + 1) begin
                reg_key[idx] <= 32'd0;
                reg_msg[idx] <= 32'd0;
            end
        end else begin
            ctrl_start <= 1'b0;
            if (S_AXI_WVALID && !w_done && aw_done) begin
                S_AXI_WREADY <= 1'b1;
                w_done       <= 1'b1;
                case (aw_addr[7:2])
                    6'h00: ctrl_start  <= S_AXI_WDATA[0];  
                    6'h02: reg_msg_len <= S_AXI_WDATA[7:0]; 
                    6'h04: reg_key[0]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h05: reg_key[1]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h06: reg_key[2]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h07: reg_key[3]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h08: reg_key[4]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h09: reg_key[5]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h0A: reg_key[6]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h0B: reg_key[7]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h0C: reg_key[8]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h0D: reg_key[9]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h0E: reg_key[10] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h0F: reg_key[11] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h10: reg_key[12] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h11: reg_key[13] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h12: reg_key[14] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h13: reg_key[15] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h14: reg_msg[0]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h15: reg_msg[1]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h16: reg_msg[2]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h17: reg_msg[3]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h18: reg_msg[4]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h19: reg_msg[5]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h1A: reg_msg[6]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h1B: reg_msg[7]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h1C: reg_msg[8]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h1D: reg_msg[9]  <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h1E: reg_msg[10] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h1F: reg_msg[11] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h20: reg_msg[12] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h21: reg_msg[13] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h22: reg_msg[14] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    6'h23: reg_msg[15] <= {S_AXI_WDATA[7:0], S_AXI_WDATA[15:8], S_AXI_WDATA[23:16], S_AXI_WDATA[31:24]};
                    default: ;
                endcase
            end else begin
                S_AXI_WREADY <= 1'b0;
                if (S_AXI_BVALID && S_AXI_BREADY) w_done <= 1'b0;
            end
        end
    end

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN)
            S_AXI_BVALID <= 1'b0;
        else if (aw_done && w_done && !S_AXI_BVALID)
            S_AXI_BVALID <= 1'b1;
        else if (S_AXI_BVALID && S_AXI_BREADY)
            S_AXI_BVALID <= 1'b0;
    end

    reg [C_S_AXI_ADDR_WIDTH-1:0] ar_addr;

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_ARREADY <= 1'b0;
            ar_addr       <= 0;
        end else begin
            if (S_AXI_ARVALID && !S_AXI_ARREADY) begin
                S_AXI_ARREADY <= 1'b1;
                ar_addr       <= S_AXI_ARADDR;
            end else
                S_AXI_ARREADY <= 1'b0;
        end
    end

    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            S_AXI_RDATA  <= 32'd0;
            S_AXI_RVALID <= 1'b0;
        end else begin
            if (S_AXI_ARREADY) begin
                S_AXI_RVALID <= 1'b1;
                case (ar_addr[7:2])
                    6'h01: S_AXI_RDATA <= {31'd0, status_done_latched};     
                    6'h24: S_AXI_RDATA <= {hmac_out[135:128], hmac_out[143:136], hmac_out[151:144], hmac_out[159:152]};      
                    6'h25: S_AXI_RDATA <= {hmac_out[103:96],  hmac_out[111:104], hmac_out[119:112], hmac_out[127:120]};      
                    6'h26: S_AXI_RDATA <= {hmac_out[71:64],   hmac_out[79:72],   hmac_out[87:80],   hmac_out[95:88]};        
                    6'h27: S_AXI_RDATA <= {hmac_out[39:32],   hmac_out[47:40],   hmac_out[55:48],   hmac_out[63:56]};        
                    6'h28: S_AXI_RDATA <= {hmac_out[7:0],     hmac_out[15:8],    hmac_out[23:16],   hmac_out[31:24]};        
                    default: S_AXI_RDATA <= 32'hDEADBEEF;
                endcase
            end else if (S_AXI_RVALID && S_AXI_RREADY)
                S_AXI_RVALID <= 1'b0;
        end
    end

endmodule
