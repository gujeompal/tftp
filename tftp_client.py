#!/usr/bin/python3
import os
import sys
import socket
import argparse
from struct import pack

DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'octet'

OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}

last_packet = None  # 마지막 전송된 패킷 저장


def resend_last_packet():
    """마지막 전송된 패킷 재전송"""
    if last_packet:
        sock.sendto(last_packet, server_address)
        print("Resent last packet.")


def send_wrq(filename, mode):
    """WRQ 메시지 전송"""
    global last_packet
    format = f'>h{len(filename)}sB{len(mode)}sB'
    wrq_message = pack(format, OPCODE['WRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    last_packet = wrq_message
    sock.sendto(last_packet, server_address)


def send_data(block_number, data, server):
    """데이터 전송"""
    global last_packet
    format = f'>hh{len(data)}s'
    data_message = pack(format, OPCODE['DATA'], block_number, data)
    last_packet = data_message
    sock.sendto(last_packet, server)


def send_rrq(filename, mode):
    """RRQ 메시지 전송"""
    global last_packet
    format = f'>h{len(filename)}sB{len(mode)}sB'
    rrq_message = pack(format, OPCODE['RRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    last_packet = rrq_message
    sock.sendto(last_packet, server_address)


def send_ack(seq_num, server):
    """ACK 메시지 전송"""
    format = '>hh'
    ack_message = pack(format, OPCODE['ACK'], seq_num)
    sock.sendto(ack_message, server)


def handle_get(filename, mode):
    """파일 다운로드 처리"""
    send_rrq(filename, mode)
    file = open(filename, 'wb')
    expected_block_number = 1

    while True:
        try:
            data, server_new_socket = sock.recvfrom(516)
        except socket.timeout:
            print("Timeout waiting for data.")
            resend_last_packet()
            continue

        opcode = int.from_bytes(data[:2], 'big')
        if opcode == OPCODE['DATA']:
            block_number = int.from_bytes(data[2:4], 'big')
            if block_number == expected_block_number:
                send_ack(block_number, server_new_socket)
                file_block = data[4:]
                file.write(file_block)
                expected_block_number += 1
            else:
                send_ack(block_number, server_new_socket)
        elif opcode == OPCODE['ERROR']:
            error_code = int.from_bytes(data[2:4], byteorder='big')
            print(ERROR_CODE[error_code])
            file.close()
            user_input = input(f"Delete partially downloaded file '{filename}'? (y/n): ").strip().lower()
            if user_input == 'y':
                os.remove(filename)
            break
        if len(file_block) < BLOCK_SIZE:
            file.close()
            print("File transfer completed")
            break


def handle_put(filename, mode):
    """파일 업로드 처리"""
    send_wrq(filename, mode)
    try:
        file = open(filename, 'rb')
        block_number = 1
        while True:
            file_block = file.read(BLOCK_SIZE)
            send_data(block_number, file_block, server_address)

            # ACK 대기
            try:
                data, server_new_socket = sock.recvfrom(516)
                opcode = int.from_bytes(data[:2], 'big')
                if opcode == OPCODE['ACK']:
                    ack_block_number = int.from_bytes(data[2:4], 'big')
                    if ack_block_number == block_number:
                        block_number += 1
                    else:
                        print("ACK block number mismatch.")
            except socket.timeout:
                print("Timeout waiting for ACK, resending block...")
                resend_last_packet()
                continue

            if len(file_block) < BLOCK_SIZE:
                print("File upload completed")
                break
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    finally:
        file.close()


# 명령줄 인자 처리
parser = argparse.ArgumentParser(description='TFTP client program')
parser.add_argument(dest="host", help="Server IP address", type=str)
parser.add_argument(dest="operation", help="get or put a file", type=str)
parser.add_argument(dest="filename", help="name of file to transfer", type=str)
parser.add_argument("-p", "--port", dest="port", type=int)
args = parser.parse_args()

server_ip = args.host
server_port = args.port if args.port else DEFAULT_PORT
server_address = (server_ip, server_port)

# 소켓 생성 및 타임아웃 설정
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5.0)

mode = DEFAULT_TRANSFER_MODE
operation = args.operation.lower()
filename = args.filename

if operation == 'get':
    handle_get(filename, mode)
elif operation == 'put':
    handle_put(filename, mode)
else:
    print(f"Invalid operation: {operation}. Use 'get' or 'put'.")

sys.exit(0)

#실행 명령어
#python tftp_client.py <host> <operation> <filename>
