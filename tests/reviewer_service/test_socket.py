import os, socket, struct, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]


def _recv_exact(sock,n):
    data=b""
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk: return data
        data+=chunk
    return data

def test_unix_socket_uses_fragment_safe_length_prefix_and_private_mode(tmp_path):
    path=tmp_path/"s"
    code="import sys; from reviewer_service.service import serve; serve(sys.argv[1],lambda req:{'canonical_payload_b64':'YQ==','signature_b64':'Yg=='},read_timeout=0.5)"
    env=os.environ.copy(); env["PYTHONPATH"]=str(ROOT/"engineering-gate")
    proc=subprocess.Popen([sys.executable,"-c",code,str(path)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+5
        while not path.exists() and time.monotonic()<deadline: time.sleep(.01)
        assert path.exists()
        assert path.stat().st_mode & 0o777==0o660
        payload=b'{"x":1}'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.connect(str(path))
            frame=struct.pack("!I",len(payload))+payload
            client.sendall(frame[:2]); client.sendall(frame[2:6]); client.sendall(frame[6:])
            size=_recv_exact(client,4)
            assert len(size)==4
            response=_recv_exact(client,struct.unpack("!I",size)[0])
            assert response==b'{"canonical_payload_b64":"YQ==","signature_b64":"Yg=="}'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.connect(str(path)); client.sendall(struct.pack("!I",65537))
            assert client.recv(1)==b""
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(2); client.connect(str(path)); client.sendall(b"\x00\x00")
            try: data=client.recv(1)
            except ConnectionResetError: data=b""
            assert data==b""
    finally:
        proc.terminate(); proc.wait(timeout=5)

def test_socket_rejects_unconfigured_peer_uid_and_times_out_partial_frames(tmp_path):
    path=tmp_path/"p"
    code="import os,sys; from reviewer_service.service import serve; serve(sys.argv[1],lambda req:(_ for _ in ()).throw(AssertionError('unauthorized handler')),authorized_uid=os.getuid()+1,read_timeout=0.2)"
    env=os.environ.copy(); env["PYTHONPATH"]=str(ROOT/"engineering-gate")
    proc=subprocess.Popen([sys.executable,"-c",code,str(path)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+5
        while not path.exists() and time.monotonic()<deadline: time.sleep(.01)
        assert path.exists()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(2); client.connect(str(path)); client.sendall(struct.pack("!I",7)+b"{}")
            try: data=client.recv(1)
            except ConnectionResetError: data=b""
            assert data==b""
    finally:
        proc.terminate(); proc.wait(timeout=5)
