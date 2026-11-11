#!/usr/bin/env python3
# Descricao: Utilitario cliente e servidor para geracao e medicao de trafego UDP
# Tecnologias: Python 3, bibliotecas nativas socket, time e sys
# Funcionamento: O modo cliente envia pacotes UDP em taxa controlada e o modo servidor contabiliza e exibe a vazao recebida por segundo

# importa os modulos necessarios para comunicacao em rede, controle de tempo e leitura de argumentos
import socket
import time
import sys

# inicia o servidor UDP para monitorar e calcular a taxa de bytes recebidos por endereco de origem
def run_server(port=5001):
    # cria o socket UDP IPv4 e associa a todas as interfaces locais na porta especificada
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[*] Servidor ouvindo na porta UDP {port}...")
    
    # inicializa o dicionario de contagem de bytes por IP e registra o tempo inicial da janela
    counts = {}
    last_print = time.time()
    
    # loop principal para recepcao continua de pacotes e exibicao periodica das metricas
    while True:
        # le um pacote do buffer de rede e extrai o endereco IP do remetente
        data, addr = sock.recvfrom(2048)
        ip = addr[0]
        # soma o tamanho da carga util recebida ao acumulador do respectivo IP de origem
        counts[ip] = counts.get(ip, 0) + len(data)
        
        # obtem o instante atual e verifica se a janela de 1 segundo foi atingida
        now = time.time()
        if now - last_print >= 1.0:
            print(f"--- Taxa de Recebimento ( últimos {now - last_print:.1f}s ) ---")
            # percorre os registros acumulados para exibir a vazao de cada host
            for host_ip, total_bytes in counts.items():
                # converte o total de bytes acumulados no segundo para kilobits por segundo
                kbps = (total_bytes * 8) / 1000.0
                print(f"Origem {host_ip}: {total_bytes/1000:.1f} KB/s ({kbps:.1f} kbps)")
            # limpa os contadores e reinicia a referencia de tempo para o proximo ciclo de medicao
            counts.clear()
            last_print = now

# inicia o cliente gerador de trafego UDP com controle de taxa de transmissao e duracao
def run_client(dst_ip, port, rate_kbps, duration):
    # cria o socket UDP IPv4 e monta o buffer de carga util fixa com 1000 bytes
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 1000
    # calcula a quantidade de pacotes por segundo necessaria para atingir a taxa alvo em kbps
    packets_per_sec = (rate_kbps * 1000.0 / 8.0) / len(payload)
    # define o intervalo de tempo ideal entre envios consecutivos para manter a cadencia
    interval = 1.0 / packets_per_sec

    print(f"[*] Enviando para {dst_ip}:{port} a ~{rate_kbps} kbps por {duration}s...")
    # calcula o instante de termino da transmissao e zera o contador de pacotes enviados
    end_time = time.time() + duration
    sent = 0
    # loop de envio de pacotes ativo ate que o tempo limite definido seja alcancado
    while time.time() < end_time:
        # registra o tempo antes do envio, transmite o pacote ao destino e incrementa o contador
        t0 = time.time()
        sock.sendto(payload, (dst_ip, port))
        sent += 1
        # calcula a duracao da operacao de envio para descontar do tempo de espera
        elapsed = time.time() - t0
        # pausa a execucao pelo tempo restante do intervalo para estabilizar a taxa de envio
        if interval > elapsed:
            time.sleep(interval - elapsed)
    print(f"[*] Concluído. Total de pacotes enviados: {sent}")

# ponto de entrada do script para validacao de argumentos e selecao do modo de operacao
if __name__ == "__main__":
    # verifica se o modo de execucao foi informado na linha de comando e exibe instrucoes caso ausente
    if len(sys.argv) < 2:
        print("Uso:")
        print("  Servidor (em h3): python3 test_traffic.py server")
        print("  Cliente  (h1/h2): python3 test_traffic.py client <IP_DEST> <TAXA_KBPS> <DURACAO_S>")
        sys.exit(1)

    # le o argumento de modo e direciona o fluxo para a rotina de servidor ou de cliente
    mode = sys.argv[1]
    if mode == "server":
        run_server()
    elif mode == "client":
        # converte os parametros de destino, taxa e duracao recebidos via terminal e inicia o envio
        dst = sys.argv[2]
        rate = float(sys.argv[3])
        dur = float(sys.argv[4])
        run_client(dst, 5001, rate, dur)