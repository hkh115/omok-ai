import pygame
import sys
import time
from collections import OrderedDict
import json
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES

BOARD_SIZE = 500
EMPTY = 40 #공백, 오목판 사이 간격
BOARD_COLOR = (205, 133, 63)
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
SQUARE_SIZE = (BOARD_SIZE - 2 * EMPTY) // 18 #오목판 크기
INF = float('inf')

class memolimit: #LRU캐시, 가장 오랫동안 사용하지 않은 값부터 삭제해서 메모리를 일정하게 유지한다
    def __init__(self, max_size=1000):
        self.__cache = OrderedDict()
        self.__max_size = max_size

    def get(self, key):
        if key in self.__cache:
            self.__cache.move_to_end(key) #조회한 값은 뒤로 이동 (사용 표시)
            return self.__cache[key]
        return None
    
    def set(self, key, value): #값 추가
        if key in self.__cache: #새로운 값
            self.__cache.move_to_end(key)
        else: #존재하는 값
            if len(self.__cache) >= self.__max_size:
                self.__cache.popitem(last=False)
            self.__cache[key] = value

    def clear(self):
        self.__cache.clear()

class CryptoManager: #암호화와 복호화에 쓰일 메서드와 값들
    def __init__(self, priv_path="priv.pem", pub_path="pub.pem", bits=2048):
        self.priv_path = priv_path
        self.pub_path = pub_path
        self.bits = bits
        self.priv_key, self.pub_key = self.generate_keypair()

    def generate_keypair(self): #암호화 키 생성
        try: #생성한 키가 있음
            with open(self.priv_path, 'rb') as f:
                priv = RSA.import_key(f.read())
            with open(self.pub_path, 'rb') as f:
                pub = RSA.import_key(f.read())
            return priv, pub
        except FileNotFoundError: #새로 만들어야 함
            key = RSA.generate(self.bits)
            priv = key
            pub = key.publickey()
            with open(self.priv_path, 'wb') as f:
                f.write(priv.export_key('PEM'))
            with open(self.pub_path, 'wb') as f:
                f.write(pub.export_key('PEM'))
            return priv, pub

    def make_sign(self, byte_data): #서명 생성
        h = SHA256.new(byte_data) #SHA256 해시값
        signer = pss.new(self.priv_key)
        signature = signer.sign(h) #실제 서명
        return signature

    def verify_sign(self, byte_data, signature): #서명 검증
        h = SHA256.new(byte_data)
        verifier = pss.new(self.pub_key) #PSS 서명으로 검증 객체 생성, 무결성 검증
        try:
            verifier.verify(h, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False

    def encrypt_gibo(self, gibo_bytes): #암호화
        aes_key = get_random_bytes(32) #AES 키
        cipher_aes = AES.new(aes_key, AES.MODE_GCM) #갈루와 카운터 모드, GCM 사용한 암호화 객체
        ciphertext, tag = cipher_aes.encrypt_and_digest(gibo_bytes) #ciphertext는 암호화된 데이터, tag는 무결성 검증에 쓰임
        nonce = cipher_aes.nonce
        rsa_cipher = PKCS1_OAEP.new(self.pub_key) #RSA 암호화 객체
        enc_key = rsa_cipher.encrypt(aes_key) #AES 키를 RSA로 암호화
        encrypted_package = { #암호화된 데이터와 이후 검증에 필요한 값들 딕셔더리로 저장
            "enc_key": base64.b64encode(enc_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        return json.dumps(encrypted_package, indent=2)

    def decrypt_gibo(self, encrypted_package_str): #복호화
        encrypted_package = json.loads(encrypted_package_str)
        enc_key = base64.b64decode(encrypted_package["enc_key"])
        nonce = base64.b64decode(encrypted_package["nonce"])
        tag = base64.b64decode(encrypted_package["tag"])
        ciphertext = base64.b64decode(encrypted_package["ciphertext"])
        rsa_cipher = PKCS1_OAEP.new(self.priv_key)
        aes_key = rsa_cipher.decrypt(enc_key)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print("복호화 실패 또는 데이터 변조 의심")
            decrypted_message = None
        return decrypted_message

class GiboManager:
    def __init__(self, crypto_manager, gibo_path="gibo_signed.json"):
        self.cm = crypto_manager
        self.gibo_path = gibo_path
        self.reset_gibo()

    def reset_gibo(self): #기보 초기화 (경로에서 불러온 후)
        with open(self.gibo_path, 'w', encoding='utf-8') as f:
            json.dump({"moves": []}, f, ensure_ascii=False, indent=2)

    def turn_to_json(self, turn_dict): #순서대로 정렬된 JSON으로 변환
        return json.dumps(turn_dict, sort_keys=True, ensure_ascii=False).encode()

    def add_move(self, move_dict): #기보에 추가
        b = self.turn_to_json(move_dict)
        signature = self.cm.make_sign(b) #서명 생성
        encrypted_move = self.cm.encrypt_gibo(b) #암호화
        entry = { #각 수를 암호화해서 기보에 추가
            "encrypted_move": encrypted_move,
            "signature": base64.b64encode(signature).decode()
        }

        try: #기보 파일 불러오기 또는 생성
            with open(self.gibo_path, 'r', encoding='utf-8') as f:
                gibo = json.load(f)
        except FileNotFoundError:
            gibo = {"moves": []}
        gibo["moves"].append(entry) #각 수 추가
        with open(self.gibo_path, 'w', encoding='utf-8') as f: #기보 파일 JSON으로 저장
            json.dump(gibo, f, ensure_ascii=False, indent=2)

    def verify_gibo(self): #서명, 무결성 검증
        results = []
        try:
            with open(self.gibo_path, "r", encoding='utf-8') as f:
                gibo = json.load(f)
        except FileNotFoundError: #파일 자체 없음
            print("기보가 파일이 존재하지 않습니다: ", self.gibo_path)
            return results
        
        for i, entry in enumerate(gibo.get("moves", [])):
            sig_b64 = entry.get("signature", "") #서명
            encrypt_package_str = entry.get("encrypted_move", "") #암호화된 수
            if not encrypt_package_str: #암호화된 수가 없음
                results.append((i, None, "암호화된 수가 없습니다."))
                continue
            try:
                decrypted_str = self.cm.decrypt_gibo(encrypt_package_str)
            except Exception as e:
                results.append((i, None, "복호화에 실패했습니다")) #복호화 과정에서의 에러
                continue

            if not sig_b64:
                results.append((i, None, False, "생성된 서명이 없습니다")) #서명이 생성되지 않음
                continue
            try:
                ok = bool(self.cm.verify_sign(decrypted_str, sig_b64))
            except Exception as e:
                results.append((i, None, False, "서명 검증에서 오류가 발생했습니다")) #검증 과정에서 에러 발생
                continue

            try:
                move = json.loads(decrypted_str) #복호화된 기보
            except Exception:
                move = None

            if ok: #서명 검증 성공
                results.append((i, move, True, None))
            else: #서명 검증 실패
                results.append((i, move, False, "올바르지 않은 서명입니다"))
        return results

    def print_gibo_encrypted(self): #암호화, 복호화된 기보 출력
        try:
            with open(self.gibo_path, 'r', encoding='utf-8') as f:
                gibo = json.load(f)
        except FileNotFoundError: #기보 파일 없음
            print("기보가 존재하지 않습니다:", self.gibo_path)
            return
        
        print("\n=== 암호화된 기보 ===")

        for i, entry in enumerate(gibo.get("moves", []), 1): #moves에 저장된 각 entry (각각의 수)
            encrypted_package_str = entry.get("encrypted_move", "")
            if not encrypted_package_str: #moves에 저장된 entry가 없음
                print(f"{i}. 암호화된 수가 없습니다.")
                continue

            encrypted_package = json.loads(encrypted_package_str)
            enc_key = encrypted_package.get("enc_key", "")
            nonce = encrypted_package.get("nonce", "")
            tag = encrypted_package.get("tag", "")
            ciphertext = encrypted_package.get("ciphertext", "")

            print(f"MOVE {i}:")
            print(f"  Encrypted AES Key: {enc_key}")
            print(f"  Nonce: {nonce}")
            print(f"  Tag: {tag}")
            print(f"  Ciphertext: {ciphertext}")

        print("\n=== 복호화된 기보 ===")

        for i, entry in enumerate(gibo.get("moves", []), 1):
            enc_str = entry["encrypted_move"]
            try:
                decrypted_bytes = self.cm.decrypt_gibo(enc_str) #복호화
                move = json.loads(decrypted_bytes)
            except Exception as e: #복호화 실패
                print(f"{i}. Decryption Faild {e}")
                continue

            player = "AI" if move["player"] == "ai" else "Human" #정보 출력
            y, x = move["y"], move["x"]
            t = datetime.fromtimestamp(move.get("t", 0)).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{i}. Player: {player}, Position: ({y}, {x}), Time: {t}")

class AiTurn: #AI
    def __init__(self, ai_player=1, human_player=2):
        self.ai = ai_player
        self.human = human_player
        self.memo = memolimit() #LRU캐시 구현 객체

    def check_win_at(self, board, y, x, player): #주어진 좌표 (y, x)를 기준으로 승패 확인
        dy = [1, 1, 0, -1] #방향
        dx = [0, 1, 1, 1]
        for t in range(4):
            cnt = 1 #연속된 수의 개수

            ty, tx = y, x
            while True: #앞 방향으로 확인
                ty += dy[t]
                tx += dx[t]
                if 0 <= ty < 19 and 0 <= tx < 19 and board[ty][tx] == player:
                    cnt += 1
                else:
                    break

            ty, tx = y, x
            while True: #뒷방향 확인
                ty -= dy[t]
                tx -= dx[t]
                if 0 <= ty < 19 and 0 <= tx < 19 and board[ty][tx] == player:
                    cnt += 1
                else:
                    break
            if cnt == 5: #연속된 수의 개수가 5라면 승리
                return True
        return False

    def checkwin(self, board, player): #모든 칸에서 각각 승패 확인
        for y in range(19):
            for x in range(19):
                if board[y][x] == player:
                    if self.check_win_at(board, y, x, player):
                        return True
        return False

    def must_do_moves(self, board, y, x, player): #강제수 판별
        if board[y][x] != 0:
            return 0
        close_three_count = 0
        dy = [1, 1, 0, -1]
        dx = [0, 1, 1, 1]
        tmp_board = [row[:] for row in board] #보드 복사해서 탐색에 사용
        tmp_board[y][x] = player
        max_score = 0 #최대 점수(가장 유리한 강제 수를 반환하도록)

        for t in range(4):
            cnt = 1
            empty_ends = 0
            for i in [1, -1]: #양방향으로 탐색
                ty, tx = y, x
                while True:
                    ty += dy[t] * i #양방향 탐색 구현 위해서 -1, 1을 곱해서 각 방향으로 탐색
                    tx += dx[t] * i
                    if 0 <= ty < 19 and 0 <= tx < 19:
                        if tmp_board[ty][tx] == player:
                            cnt += 1 #연속된 수의 개수
                        elif tmp_board[ty][tx] == 0:
                            empty_ends += 1 #열린 끝부분 수 (0, 1, 2)
                            break
                        else:
                            break
                    else:
                        break
            
            score = 0
            if cnt == 5: #이기는 경우
                score = 3
            elif cnt == 4: #열린 사, 닫힌 사 순서대로 점수 부여
                if empty_ends == 2:
                    score = 2
                elif empty_ends == 1:
                    score = 1
            elif cnt == 3 and empty_ends == 2: #열린 삼
                score = 1
            
            if score > max_score: #최대 점수
                max_score = score
            
            if cnt == 3 and empty_ends >= 1: #닫힌 3의 개수
                close_three_count += 1
                
        if close_three_count >= 2: #같은 위치로부터 닫힌 3이 두개
            max_score = max(max_score, 1)
            
        return max_score

    def eval_board(self, board): #보드 평가 함수
        if self.checkwin(board, self.ai): #승패 결정된 경우
            return INF
        if self.checkwin(board, self.human):
            return -INF
        dy = [1, 1, 0, -1]
        dx = [0, 1, 1, 1]
        human_sum, ai_sum = 0, 0
        ai_scores = { #AI와 인간 가중치 다르게 부여 -> 인간의 수 더 강하게 방어하도록 유도
            "open_two": 10,
            "close_two": 2,
            "open_three": 800,
            "close_three": 10,
            "open_four": 40000,
            "close_four": 5000,
            "double_three": 15000,
            "double_four": 80000
        }
        human_scores = {
            "open_two": 10,
            "close_two": 2,
            "open_three": 1000,
            "close_three": 10,
            "open_four": 50000,
            "close_four": 5000,
            "double_three": 20000,
            "double_four": 1000000,
        }
        open3 = {1: 0, 2: 0} #열린 3의 개수, AI는 1, 인간은 2로 구분해서 저장
        open4 = {1: 0, 2: 0}

        for y in range(19):
            for x in range(19):
                player = board[y][x]

                if board[y][x] == 0: #빈 칸은 평가할 필요 없음
                    continue

                for t in range(4): #각 방향마다 판별
                    py, px = y - dy[t], x - dx[t]
                    if 0 <= py < 19 and 0 <= px < 19 and board[py][px] == player:
                        continue
                    cnt = 1 #연속된 수의 개수
                    ty, tx = y, x

                    while True:
                        ty += dy[t]
                        tx += dx[t]
                        if 0 <= ty < 19 and 0 <= tx < 19 and board[ty][tx] == player:
                            cnt += 1
                        else:
                            break
                        if cnt == 4:
                            break

                    start_open, end_open = 0, 0 #양 끝부분 열렸는지 여부
                    sy, sx, ey, ex = y - dy[t], x - dx[t], y + cnt * dy[t], x + cnt * dx[t]
                    start_open = (0 <= sy < 19 and 0 <= sx < 19 and board[sy][sx] == 0)
                    end_open = (0 <= ey < 19 and 0 <= ex < 19 and board[ey][ex] == 0)
                    val = 0

                    if start_open and end_open: #양쪽이 열린 경우
                        if cnt == 2:
                            val = ai_scores["open_two"] if player == self.ai else human_scores["open_two"]
                        elif cnt == 3:
                            open3[player] += 1 #열린 3 개수 저장
                            val = ai_scores["open_three"] if player == self.ai else human_scores["open_three"]
                        elif cnt == 4:
                            open4[player] += 1 #열린 4 개수 저장
                            val = ai_scores["open_four"] if player == self.ai else human_scores["open_four"]

                    elif start_open or end_open: #한쪽만 열린 경우
                        if cnt == 2:
                            val = ai_scores["close_two"] if player == self.ai else human_scores["close_two"]
                        elif cnt == 3:
                            val = ai_scores["close_three"] if player == self.ai else human_scores["close_three"]
                        elif cnt == 4:
                            val = ai_scores["close_four"] if player == self.ai else human_scores["close_four"]

                    if player == self.ai:
                        ai_sum += val
                    else:
                        human_sum += val

        if open3[1] >= 2: #열린 삼, 사에 따라 추가 점수 부여
            ai_sum += ai_scores["double_three"]
        if open4[1] >= 2:
            ai_sum += ai_scores["double_four"]
        if open3[2] >= 2:
            human_sum += human_scores["double_three"]
        if open4[2] >= 2:
            human_sum += human_scores["double_four"]
        return ai_sum - human_sum

    def find_candidates(self, board, player): #후보 수 탐색
        done_moves = [(y, x) for y in range(19) for x in range(19) if board[y][x] != 0] #이미 수가 놓인 칸들
        if not done_moves: #첫 수는 중앙에 놓도록
            return [(9, 9)]
        candidates = []

        for y in range(19):
            for x in range(19):
                if board[y][x] != 0:
                    continue
                min_dis = min(abs(y - ty) + abs(x - tx) for ty, tx in done_moves) #거리
                if min_dis <= 2: #거리가 2 이하인 칸들만 후보로 고려
                    board[y][x] = player
                    candidates.append((self.eval_board(board), -min_dis, y, x)) #평가 점수, 거리, 좌표 저장(거리는 가까울수록 우선순위 높도록 음수로 저장)
                    board[y][x] = 0

        if not candidates: #주변 수가 없는 경우 중앙에 놓도록
            board[9][9] = player
            candidates = [(self.eval_board(board), 0, 9, 9)]
            board[9][9] = 0

        candidates.sort(reverse=(player == self.ai)) #정렬
        final_candidates = [(y, x) for s, d, y, x in candidates[:7]] #상위 7개의 수만 후보 수로 고려
        return final_candidates

    def board_to_tuple(self, board):
        return tuple(tuple(row) for row in board)

    def minimax(self, board, depth, alpha, beta, is_max, last_move=None): #minimax 알고리즘 + alpha-beta 가지치기
        key = (self.board_to_tuple(board), is_max, depth)
        result = self.memo.get(key)
        if result is not None:
            return result
        
        if last_move:
            ly, lx = last_move
            last_player = self.human if is_max else self.ai
            if self.check_win_at(board, ly, lx, last_player): #승패 결정된 경우, 승리한 플레이어에 따라 점수 반환
                score = INF if last_player == self.ai else -INF
                self.memo.set(key, score)
                return score

        if depth > 5: #깊이 제한 초과한 경우
            result = self.eval_board(board)
            self.memo.set(key, result)
            return result
            
        if is_max:  # ai
            bs = -INF
            for y, x in self.find_candidates(board, self.ai): #후보 수
                if board[y][x] == 0:
                    board[y][x] = self.ai
                    score = self.minimax(board, depth + 1, alpha, beta, False, (y, x)) #재귀적으로 탐색
                    board[y][x] = 0
                    bs = max(bs, score)
                    alpha = max(alpha, score)
                    if beta <= alpha: return bs #alpha는 지금까지의 최댓값, beta는 지금까지의 최솟값, alpha가 beta보다 크거나 같아지면 더 이상 탐색할 필요 없음
            self.memo.set(key, bs) #LRU 캐시에 저장
            return bs
        else:  # 사람
            bs = INF
            for y, x in self.find_candidates(board, self.human):
                if board[y][x] == 0:
                    board[y][x] = self.human
                    score = self.minimax(board, depth + 1, alpha, beta, True, (y, x))
                    board[y][x] = 0
                    bs = min(bs, score)
                    beta = min(beta, score)
                    if beta <= alpha: return bs
            self.memo.set(key, bs)
            return bs

    def bestmove(self, board): #실제로 놓을 수 결정
        ai_moves = []
        human_moves = []
        cands_ai = self.find_candidates(board, self.ai) #AI와 인간 각각 후보 수 탐색
        cands_human = self.find_candidates(board, self.human)
        all_candidates = list(OrderedDict.fromkeys(cands_ai + cands_human)) #전체 후보 수
        for y, x in all_candidates: #각 후보 수에 대해서 강제 수인지 판별
            h_score = self.must_do_moves(board, y, x, self.human)
            if h_score > 0:
                human_moves.append((h_score, y, x))
            a_score = self.must_do_moves(board, y, x, self.ai)
            if a_score > 0:
                ai_moves.append((a_score, y, x))
        
        ai_moves.sort(key=lambda x: x[0], reverse=True) #AI는 높은 점수부터, 인간은 낮은 점수부터 정렬해서 우선순위 결정
        human_moves.sort(key=lambda x: x[0], reverse=True)

        if ai_moves and ai_moves[0][0] == 3: #당장 AI가 이길 수 있는 경우
            return (ai_moves[0][1], ai_moves[0][2])
            
        if human_moves and human_moves[0][0] == 3: #안막으면 사람이 이기는 경우
            return (human_moves[0][1], human_moves[0][2])
            
        if ai_moves and ai_moves[0][0] == 2: #AI가 다음 수에 이길 수 있는 경우
            return (ai_moves[0][1], ai_moves[0][2])
        
        if human_moves and human_moves[0][0] == 2: #사람이 다음 수에 이길 수 있는 경우
            return (human_moves[0][1], human_moves[0][2])

        if human_moves: #강제 수가 없는 경우 -> 먼저 사람의 가장 위협적인 수 방어
             best_score = float('inf')
             best_move = None
             for s, y, x in human_moves:
                 board[y][x] = self.human
                 score = self.eval_board(board)
                 board[y][x] = 0
                 if score < best_score:
                     best_score = score #가장 높은 점수
                     best_move = (y, x) #가장 좋은 수
             return best_move
             
        if ai_moves: #방어할 필요 없는 경우 -> 공격
             best_score = -float('inf')
             best_move = None
             for s, y, x in ai_moves:
                 board[y][x] = self.ai
                 score = self.eval_board(board)
                 board[y][x] = 0
                 if score > best_score:
                     best_score = score
                     best_move = (y, x)
             return best_move
        
        bestscore = -float('inf')
        best_move = None
        cands_ai = self.find_candidates(board, self.ai)
        cands_human = self.find_candidates(board, self.human)
        minimax_candidates = list(OrderedDict.fromkeys(cands_ai + cands_human)) #minimax 후보 수 탐색에 사용할 전체 후보 수
        
        for y, x in minimax_candidates:
            board[y][x] = self.ai
            score = self.minimax(board, 1, -INF, INF, False, (y, x)) #minimax로 탐색
            board[y][x] = 0
            if score > bestscore:
                bestscore = score
                best_move = (y, x)
        return best_move

class OmokGame: #게임 진행
    def __init__(self): #게임 초기화, 화면 설정
        pygame.init()
        self.screen = pygame.display.set_mode([BOARD_SIZE, BOARD_SIZE])
        self.text_font = pygame.font.SysFont('Times New Roman', 30)
        self.board = [[0 for _ in range(19)] for _ in range(19)]
        self.ai_player = 1
        self.human_player = 2
        self.turn = 1
        self.last_ai_move = None
        self.running = True

        self.crypto_manager = CryptoManager() #암호화 객체 생성
        self.gibo_manager = GiboManager(self.crypto_manager) #기보 객체 생성
        self.ai = AiTurn(self.ai_player, self.human_player) #AI 객체 생성

        self.screen.fill(BOARD_COLOR)
        self.draw_grid()
        pygame.display.update()

    def draw_grid(self): #오목판 그리기
        for i in range(19):
            sp = EMPTY + i * SQUARE_SIZE
            pygame.draw.line(self.screen, BLACK, [EMPTY, sp], [EMPTY + SQUARE_SIZE * 18, sp], 1)
            pygame.draw.line(self.screen, BLACK, [sp, EMPTY], [sp, EMPTY + SQUARE_SIZE * 18], 1)

    def draw_text(self, string, text_col, bg_col, padding=10): #승패 메시지 출력
        img = self.text_font.render(string, True, text_col)
        text_rect = img.get_rect(center=(self.screen.get_width() // 2, self.screen.get_height() // 2))
        bg_rect = text_rect.inflate(padding * 2, padding * 2)
        pygame.draw.rect(self.screen, bg_col, bg_rect, border_radius=8)
        self.screen.blit(img, text_rect)

    def verify_and_exit(self): #게임 종료 시 기보 검증 후 결과 출력
        results = self.gibo_manager.verify_gibo() #기보 검증 결과
        if not results: #검증 결과 자체가 없는 경우
            all_ok = False
        else:
            all_ok = all(item[2] is True for item in results) #서명 검증이 모두 성공한 경우
        if all_ok:
            print("기보의 모든 수가 정상적으로 검증되었습니다.")
            self.gibo_manager.print_gibo_encrypted()
        else:
            print("기보 검증을 실패하였습니다.")
        pygame.quit()
        sys.exit()

    def play(self): #게임 루프
        while self.running:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.verify_and_exit()

                if self.turn == 1: #사람 차례
                    if event.type == pygame.MOUSEBUTTONDOWN: #클릭한 좌표에 수 놓기
                        pos = pygame.mouse.get_pos()
                        cx = round((pos[0] - EMPTY) / SQUARE_SIZE)
                        cy = round((pos[1] - EMPTY) / SQUARE_SIZE)
                        if 0 <= cx < 19 and 0 <= cy < 19 and self.board[cy][cx] == 0:
                            if self.last_ai_move is not None:
                                ay, ax = self.last_ai_move
                                px = EMPTY + ax * SQUARE_SIZE
                                py = EMPTY + ay * SQUARE_SIZE
                                pygame.draw.circle(self.screen, WHITE, [px, py], 4)
                                pygame.display.update()
                            
                            self.board[cy][cx] = self.human_player
                            move = {"y": cy, "x": cx, "player": "human", "t": int(time.time())} #기보에 기록
                            self.gibo_manager.add_move(move)
                            
                            px, py = EMPTY + cx * SQUARE_SIZE, EMPTY + cy * SQUARE_SIZE #화면에 수 그리기
                            pygame.draw.circle(self.screen, BLACK, [px, py], 9)
                            pygame.display.update()

                            if self.ai.checkwin(self.board, self.human_player): #승리한 경우 메시지 출력 후 게임 종료
                                self.draw_text("Black win", BLACK, WHITE)
                                pygame.display.update()
                                time.sleep(1)
                                self.verify_and_exit()
                            self.turn = 0
                else: #AI 차례
                    best = self.ai.bestmove(self.board) #최적의 수
                    if best:
                        by, bx = best
                        self.board[by][bx] = self.ai_player
                        move = {"y": by, "x": bx, "player": "ai", "t": int(time.time())}
                        self.gibo_manager.add_move(move)

                        px, py = EMPTY + bx * SQUARE_SIZE, EMPTY + by * SQUARE_SIZE
                        pygame.draw.circle(self.screen, WHITE, [px, py], 9)
                        pygame.draw.circle(self.screen, (255, 0, 0), [px, py], 4) #AI가 놓은 수는 빨간 점으로 표시(다음 수 놓을때 삭제)
                        pygame.display.update()
                        self.last_ai_move = (by, bx) #AI가 놓은 수 저장해서 다음에 화면에서 표시할 때 사용 (빨간 점 지울때)

                        if self.ai.checkwin(self.board, self.ai_player): #승리한 경우
                            self.draw_text("White win", WHITE, BLACK)
                            pygame.display.update()
                            time.sleep(1)
                            self.verify_and_exit()
                    self.turn = 1

if __name__ == "__main__": #게임 실행
    game = OmokGame()
    game.play()
