import socket
import struct
import os
import argparse
import hashlib
import hmac
import logging
from typing import Tuple, Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    import gmpy2
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False
    logging.warning("gmpy2 未安装，将使用 Python 内置 pow() 进行大数运算（较慢）")

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

IKE_PORT = 500
NONCE_LEN = 16
AES_KEY_LEN = 16
HMAC_KEY_LEN = 20
DH_KEY_LEN = 256 

MSG_SA_PROPOSE = 1
MSG_SA_ACCEPT = 2
MSG_KE_NONCE = 3
MSG_AUTH = 5
MSG_DATA = 10

DH_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_PRIME = int(DH_PRIME_HEX, 16)
DH_GENERATOR = 2


class IKESimulator:
    """IKE 协议模拟器"""

    def __init__(self, role: str, board_ip: str, psk: bytes, local_port: int = 0, encoding: str = 'utf-8'):
        self.role = role                             
        self.board_ip = board_ip
        self.psk = psk
        self.local_port = local_port if local_port else IKE_PORT
        self.encoding = encoding

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(60.0)

        self.cky_i = os.urandom(8)
        self.cky_r = b'\x00' * 8

        self.dh_private = int.from_bytes(os.urandom(DH_KEY_LEN), 'big') % DH_PRIME
        self.dh_public = self._mod_exp(DH_GENERATOR, self.dh_private, DH_PRIME)
        self.dh_peer_public: Optional[int] = None
        self.dh_shared: Optional[int] = None

        self.nonce_i = os.urandom(NONCE_LEN)
        self.nonce_r = b'\x00' * NONCE_LEN

        self.skeyid: Optional[bytes] = None
        self.skeyid_d: Optional[bytes] = None
        self.skeyid_a: Optional[bytes] = None
        self.skeyid_e: Optional[bytes] = None

        self.enc_key: Optional[bytes] = None
        self.auth_key: Optional[bytes] = None

    @staticmethod
    def _mod_exp(base: int, exp: int, mod: int) -> int:
        """模幂运算，优先使用 gmpy2 加速"""
        if HAS_GMPY2:
            return int(gmpy2.powmod(base, exp, mod))
        return pow(base, exp, mod)

    def _hmac_sha1(self, key: bytes, msg: bytes) -> bytes:
        """HMAC-SHA1 计算"""
        return hmac.new(key, msg, hashlib.sha1).digest()

    def _derive_keys(self):
        """
        派生 IKE 密钥（PSK 模式）

        NOTE: 按照 RFC 2409 Section 5 计算:
          SKEYID   = HMAC-SHA1(PSK, Ni || Nr)
          SKEYID_d = HMAC-SHA1(SKEYID, DH_shared || CKY_I || CKY_R || 0)
          SKEYID_a = HMAC-SHA1(SKEYID, SKEYID_d || DH_shared || CKY_I || CKY_R || 1)
          SKEYID_e = HMAC-SHA1(SKEYID, SKEYID_a || DH_shared || CKY_I || CKY_R || 2)
        """
        dh_shared_bytes = self.dh_shared.to_bytes(DH_KEY_LEN, 'big')

        self.skeyid = self._hmac_sha1(self.psk, self.nonce_i + self.nonce_r)
        logger.info(f"SKEYID: {self.skeyid.hex()}")

        self.skeyid_d = self._hmac_sha1(
            self.skeyid,
            dh_shared_bytes + self.cky_i + self.cky_r + b'\x00'
        )

        self.skeyid_a = self._hmac_sha1(
            self.skeyid,
            self.skeyid_d + dh_shared_bytes + self.cky_i + self.cky_r + b'\x01'
        )

        self.skeyid_e = self._hmac_sha1(
            self.skeyid,
            self.skeyid_a + dh_shared_bytes + self.cky_i + self.cky_r + b'\x02'
        )

        self.enc_key = self.skeyid_e[:AES_KEY_LEN]
        self.auth_key = self.skeyid_a[:HMAC_KEY_LEN]

        logger.info(f"AES Key:  {self.enc_key.hex()}")
        logger.info(f"HMAC Key: {self.auth_key.hex()}")

    def _build_header(self, msg_type: int, payload: bytes) -> bytes:
        """构造 IKE 消息头"""
        return struct.pack('!BBH', msg_type, 0, len(payload)) +\
               self.cky_i + self.cky_r + payload

    def _parse_header(self, data: bytes) -> Tuple[int, bytes, bytes, bytes]:
        """解析 IKE 消息头"""
        msg_type, _, payload_len = struct.unpack('!BBH', data[:4])
        cky_i_recv = data[4:12]
        cky_r_recv = data[12:20]
        payload = data[20:20 + payload_len]
        return msg_type, cky_i_recv, cky_r_recv, payload

    def _aes_encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """AES-128-CBC 加密"""
        iv = os.urandom(16)
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, 16))
        return iv, ciphertext

    def _aes_decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """AES-128-CBC 解密"""
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        try:
            return unpad(plaintext, 16)
        except ValueError:
            return plaintext.rstrip(b'\x00')

    def run_initiator(self):
        """执行 Initiator 角色的 IKE 密钥协商"""
        self.sock.bind(('0.0.0.0', self.local_port))
        target = (self.board_ip, IKE_PORT)

        logger.info("=== Msg 1: 发送 SA 提议 ===")
        sa_payload = b'AES128-CBC:SHA1:DH14:PSK'             
        msg1 = self._build_header(MSG_SA_PROPOSE, sa_payload)
        self.sock.sendto(msg1, target)

        logger.info("等待 Msg 2...")
        data, addr = self.sock.recvfrom(4096)
        msg_type, cky_i, cky_r, payload = self._parse_header(data)
        assert msg_type == MSG_SA_ACCEPT, f"期望 SA_ACCEPT，收到 {msg_type}"
        self.cky_r = cky_r
        logger.info(f"=== Msg 2: SA 已协商 (参数: {payload.decode()}) ===")

        logger.info("=== Msg 3: 发送 KE + Nonce ===")
        dh_pub_bytes = self.dh_public.to_bytes(DH_KEY_LEN, 'big')
        ke_payload = dh_pub_bytes + self.nonce_i
        msg3 = self._build_header(MSG_KE_NONCE, ke_payload)
        self.sock.sendto(msg3, target)

        logger.info("等待 Msg 4...")
        data, addr = self.sock.recvfrom(4096)
        msg_type, _, _, payload = self._parse_header(data)
        assert msg_type == MSG_KE_NONCE
        self.dh_peer_public = int.from_bytes(payload[:DH_KEY_LEN], 'big')
        self.nonce_r = payload[DH_KEY_LEN:DH_KEY_LEN + NONCE_LEN]
        logger.info("=== Msg 4: 收到对端 DH 公钥 + Nonce ===")

        self.dh_shared = self._mod_exp(self.dh_peer_public, self.dh_private, DH_PRIME)

        self._derive_keys()

        logger.info("=== Msg 5: 发送加密的身份 + HASH ===")
        id_data = b'INITIATOR_ID'
        hash_i = self._hmac_sha1(
            self.skeyid,
            self.dh_public.to_bytes(DH_KEY_LEN, 'big') +
            self.dh_peer_public.to_bytes(DH_KEY_LEN, 'big') +
            self.cky_i + self.cky_r + sa_payload + id_data
        )
        auth_payload = id_data + hash_i
        iv, encrypted = self._aes_encrypt(auth_payload)
        mac = self._hmac_sha1(self.auth_key, iv + encrypted)
        msg5 = self._build_header(MSG_AUTH, iv + encrypted + mac)
        self.sock.sendto(msg5, target)

        logger.info("等待 Msg 6...")
        data, addr = self.sock.recvfrom(4096)
        msg_type, _, _, payload = self._parse_header(data)
        assert msg_type == MSG_AUTH
        peer_iv = payload[:16]
        peer_mac = payload[-HMAC_KEY_LEN:]
        peer_enc = payload[16:-HMAC_KEY_LEN]
        computed_mac = self._hmac_sha1(self.auth_key, peer_iv + peer_enc)
        if peer_mac != computed_mac:
            logger.error("HMAC 验证失败！")
            return False
        peer_auth = self._aes_decrypt(peer_iv, peer_enc)
        peer_id = peer_auth[:-HMAC_KEY_LEN]
        peer_hash = peer_auth[-HMAC_KEY_LEN:]
        logger.info(f"=== Msg 6: 对端身份 = {peer_id.decode()} ===")

        logger.info("   IKE SA 建立成功！密钥协商完成。")
        logger.info(f"   加密密钥: {self.enc_key.hex()}")
        logger.info(f"   认证密钥: {self.auth_key.hex()}")

        return True

    def run_responder(self):
        """执行 Responder 角色的 IKE 密钥协商"""
        self.sock.bind(('0.0.0.0', IKE_PORT))
        logger.info(f"Responder 监听 UDP:{IKE_PORT}...")

        logger.info("等待 Msg 1...")
        data, addr = self.sock.recvfrom(4096)
        msg_type, cky_i, cky_r, payload = self._parse_header(data)
        assert msg_type == MSG_SA_PROPOSE
        self.cky_i = cky_i
        sa_payload = payload
        logger.info(f"=== Msg 1: 收到 SA 提议 (参数: {payload.decode()}) ===")

        logger.info("=== Msg 2: 发送 SA 接受 ===")
        self.cky_r = os.urandom(8)
        msg2 = self._build_header(MSG_SA_ACCEPT, sa_payload)
        self.sock.sendto(msg2, addr)

        logger.info("等待 Msg 3...")
        data, addr = self.sock.recvfrom(4096)
        msg_type, _, _, payload = self._parse_header(data)
        assert msg_type == MSG_KE_NONCE
        self.dh_peer_public = int.from_bytes(payload[:DH_KEY_LEN], 'big')
        self.nonce_i = payload[DH_KEY_LEN:DH_KEY_LEN + NONCE_LEN]
        logger.info("=== Msg 3: 收到 Initiator DH 公钥 + Nonce ===")

        logger.info("=== Msg 4: 发送 KE + Nonce ===")
        self.nonce_r = os.urandom(NONCE_LEN)
        dh_pub_bytes = self.dh_public.to_bytes(DH_KEY_LEN, 'big')
        ke_payload = dh_pub_bytes + self.nonce_r
        msg4 = self._build_header(MSG_KE_NONCE, ke_payload)
        self.sock.sendto(msg4, addr)

        self.dh_shared = self._mod_exp(self.dh_peer_public, self.dh_private, DH_PRIME)
        logger.info(f"DH 共享密钥 (前16字节): {self.dh_shared.to_bytes(DH_KEY_LEN, 'big')[:16].hex()}")

        self._derive_keys()

        logger.info("等待 Msg 5...")
        data, addr = self.sock.recvfrom(4096)
        msg_type, _, _, payload = self._parse_header(data)
        assert msg_type == MSG_AUTH
        peer_iv = payload[:16]
        peer_mac = payload[-HMAC_KEY_LEN:]
        peer_enc = payload[16:-HMAC_KEY_LEN]
        computed_mac = self._hmac_sha1(self.auth_key, peer_iv + peer_enc)
        if peer_mac != computed_mac:
            logger.error("HMAC 验证失败！")
            return False
        peer_auth = self._aes_decrypt(peer_iv, peer_enc)
        logger.info(f"=== Msg 5: 收到 Initiator 认证, ID={peer_auth[:-HMAC_KEY_LEN].decode()} ===")

        logger.info("=== Msg 6: 发送 Responder 认证 ===")
        id_data = b'RESPONDER_ID'
        hash_r = self._hmac_sha1(
            self.skeyid,
            self.dh_public.to_bytes(DH_KEY_LEN, 'big') +
            self.dh_peer_public.to_bytes(DH_KEY_LEN, 'big') +
            self.cky_r + self.cky_i + sa_payload + id_data
        )
        auth_payload = id_data + hash_r
        iv, encrypted = self._aes_encrypt(auth_payload)
        mac = self._hmac_sha1(self.auth_key, iv + encrypted)
        msg6 = self._build_header(MSG_AUTH, iv + encrypted + mac)
        self.sock.sendto(msg6, addr)

        logger.info("   IKE SA 建立成功！密钥协商完成。")
        return True

    def send_encrypted(self, message: str):
        """使用已建立的 SA 发送加密消息"""
        if not self.enc_key:
            logger.error("SA 未建立，无法发送加密消息")
            return
        iv, encrypted = self._aes_encrypt(message.encode(self.encoding))
        mac = self._hmac_sha1(self.auth_key, iv + encrypted)
        payload = iv + encrypted + mac
        pkt = self._build_header(MSG_DATA, payload)
        self.sock.sendto(pkt, (self.board_ip, IKE_PORT))
        logger.info(f"已发送加密消息: {message}")

    def receive_encrypted(self) -> Optional[str]:
        """接收并解密消息"""
        data, addr = self.sock.recvfrom(4096)
        msg_type, _, _, payload = self._parse_header(data)
        if msg_type != MSG_DATA:
            logger.warning(f"非数据消息: type={msg_type}")
            return None
        iv = payload[:16]
        mac_received = payload[-20:]
        encrypted = payload[16:-20]
        mac_computed = self._hmac_sha1(self.auth_key, iv + encrypted)
        if mac_received != mac_computed:
            logger.error("HMAC 验证失败！")
            return None
        plaintext = self._aes_decrypt(iv, encrypted)
        try:
            return plaintext.decode(self.encoding)
        except UnicodeDecodeError:
            logger.error(f"无法使用 {self.encoding} 解码明文: {plaintext.hex()}")
            return f"[UNDECODABLE: {plaintext.hex()}]"


def main():
    parser = argparse.ArgumentParser(description='IKE 协议模拟器 (PC 端)')
    parser.add_argument('--role', choices=['initiator', 'responder'],
                        required=True, help='角色: initiator 或 responder')
    parser.add_argument('--board-ip', default='192.168.1.10',
                        help='FPGA 板 IP 地址')
    parser.add_argument('--psk', default='mysecretkey',
                        help='预共享密钥')
    parser.add_argument('--port', type=int, default=0,
                        help='本地端口（默认: initiator 随机, responder 500）')
    parser.add_argument('--encoding', default=None,
                        help='字符编码 (例如: utf-8, gbk)。如果不指定，在 Windows 下建议使用 gbk 以匹配 SDK 串口终端。')
    args = parser.parse_args()

    selected_encoding = args.encoding
    if selected_encoding is None:
        if sys.platform == 'win32':
            selected_encoding = 'gbk'
            logger.info("检测到 Windows 环境，默认使用 'gbk' 编码以匹配 Vitis/Serial 终端。")
            logger.info("如果您的终端支持 UTF-8，请手动指定 --encoding utf-8")
        else:
            selected_encoding = 'utf-8'
    logger.info(f"当前使用的字符编码: {selected_encoding}")

    sim = IKESimulator(
        role=args.role,
        board_ip=args.board_ip,
        psk=args.psk.encode(),
        local_port=args.port,
        encoding=selected_encoding
    )

    try:
        if args.role == 'initiator':
            success = sim.run_initiator()
        else:
            success = sim.run_responder()

        if success:
            logger.info("\n=== 进入加密通讯模式 (输入消息或 'quit' 退出) ===")
            while True:
                msg = input("> ")
                if msg.lower() == 'quit':
                    break
                sim.send_encrypted(msg)
                try:
                    reply = sim.receive_encrypted()
                    if reply:
                        logger.info(f"收到解密消息: {reply}")
                except socket.timeout:
                    logger.warning("等待回复超时")

    except KeyboardInterrupt:
        logger.info("\n用户中断")
    except Exception as e:
        logger.error(f"错误: {e}")
    finally:
        sim.sock.close()


if __name__ == '__main__':
    main()
