# Relatório Prático: Detecção e Tratamento de Anomalias em P4
**Alunos:** Enzo Silveira, Guilherme Pimentel, Luan Streck

Este documento explica de forma direta como o trabalho foi modelado, implementado e testado no Mininet, cobrindo cada um dos critérios de avaliação da disciplina.

---

## 1. Definição e Justificativa da Anomalia

* **O que é a anomalia:** Escolhemos trabalhar com **Fluxo Elefante (rajada contínua de tráfego com volume/taxa excessivos)**.
* **Por que é uma anomalia (Justificativa):**
  * Na nossa rede, o link de saída entre o switch `s1` e o servidor `h3` tem capacidade limitada de **$2\text{ Mbps}$** ($\approx 250\text{ KB/s}$).
  * O host `h1` representa um tráfego comum/legítimo, enviando a **$\approx 400\text{ kbps}$** ($50\text{ KB/s}$).
  * O host `h2` gera a anomalia, injetando uma taxa de **$\approx 2500\text{ kbps}$** ($312\text{ KB/s}$).
  * Como a taxa de `h2` é maior do que a capacidade total do cabo ($2\text{ Mbps}$), ele estrangula a fila do switch. Sem controle, isso gera congestionamento severo (*bufferbloat*), derruba pacotes do `h1` e destrói o tempo de resposta da rede.
* **Critérios e Limiares:**
  * O switch calcula a taxa acumulada em janelas de tempo de **$1\text{ segundo}$** ($1.000.000\ \mu\text{s}$).
  * `THRESHOLD_LOW = 100.000 bytes` ($\approx 100\text{ KB/s}$ ou $800\text{ kbps}$): ultrapassando isso, o fluxo já é considerado anômalo.
  * `THRESHOLD_HIGH = 200.000 bytes` ($\approx 200\text{ KB/s}$ ou $1.6\text{ Mbps}$): indica uma anomalia severa.

---

## 2. Implementação do Detector em P4

Toda a lógica foi feita **100% no Data Plane** dentro do arquivo `anomalias.p4`, sem precisar incomodar o controlador SDN a cada pacote.

* **Memória no switch (`register`):**
  * Criamos dois registradores de 1024 posições:
    * `reg_byte_count`: guarda a quantidade de bytes que aquele host já enviou na janela atual.
    * `reg_last_time`: guarda a estampa de tempo (timestamp) de quando a janela começou.
* **Separando os fluxos por host:**
  * Usamos a função `hash` com algoritmo `crc16` em cima do IP de origem (`hdr.ipv4.srcAddr`). Isso gera um índice de 0 a 1023 na memória do switch para cada máquina.
* **Lógica da Janela Temporal:**
  * Pegamos o tempo do pacote atual com `standard_metadata.ingress_global_timestamp`.
  * Comparamos com o tempo gravado em `reg_last_time`:
    * Se já passou mais de $1\text{ segundo}$ ($\Delta t > 1.000.000\ \mu\text{s}$), a janela anterior acabou: resetamos o contador para o tamanho do pacote atual e salvamos o novo tempo.
    * Se ainda está dentro do mesmo segundo, somamos o tamanho do pacote (`packet_length`) ao total acumulado.
  * Se o acumulado passar de $100\text{ KB}$, o pacote entra imediatamente na regra de mitigação.

---

## 3. Estratégias de Tratamento

Criamos uma tabela chamada `mitigation_config` no P4 para alternar a ação tomada quando o limite é estourado:

1. **Cenário 0 — Sem Mitigação (`strat = 0`):**
   * O switch não faz nada além de encaminhar. Serve como grupo de controle para demonstrar o estrago que o fluxo anômalo faz na rede.
2. **Estratégia A — Descarte Total (`strat = 1`):**
   * Assim que o contador passa de $100\text{ KB/s}$, qualquer pacote seguinte daquele mesmo host dentro do segundo atual sofre `drop()` imediato (`mark_to_drop`).
   * *Objetivo:* Cortar o mal pela raiz, limpando a fila do switch e protegendo a latência do tráfego legítimo.
3. **Estratégia B — Descarte Probabilístico (`strat = 2`):**
   * O switch sorteia um número de 0 a 99 usando `random()`.
   * Se a anomalia for moderada (entre $100$ e $200\text{ KB/s}$), há **$40\%$ de chance de drop** (`rand_val < 40`).
   * Se for severa (acima de $200\text{ KB/s}$), há **$80\%$ de chance de drop** (`rand_val < 80`).
   * *Objetivo:* Em vez de matar o fluxo de vez, atenua o tráfego proporcionalmente para aproveitar a banda livre sem derrubar o vizinho.

---

## 4. Experimentos e Avaliação de Desempenho

### Como testamos no Mininet
* Topologia com `h1`, `h2` e `h3` ligados no switch `s1`. O link `s1 -> h3` foi limitado a $2\text{ Mbps}$.
* Usamos um script Python (`test_traffic.py`) gerando datagramas UDP com opção `-u` (sem buffer) e medimos as taxas segundo a segundo em `h3`.
* Rodamos o comando `ping` de `h1` para `h3` para medir latência (RTT) e perda de pacotes enquanto a anomalia acontecia.

### Dados Reais Coletados nos Testes

| Cenário | Taxa h1 (Legítimo)<br>*(Enviado: ~400 kbps)* | Taxa h2 (Anômalo)<br>*(Enviado: ~2500 kbps)* | RTT Médio (Ping h1) | Perda (Ping h1) | O que aconteceu na rede? |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **0. Sem Mitigação** | **$6{,}0\text{ a }39{,}0\text{ KB/s}$**<br>*(Caiu até 48 kbps)* | **$187{,}0\text{ a }241{,}0\text{ KB/s}$**<br>*(Quase os 2 Mbps)* | **$1809{,}15\text{ ms}$**<br>*(~1.8 segundos)* | **$60\%$** | `h2` tomou conta do canal. A fila encheu, gerou *bufferbloat* e `h1` quase não conseguiu falar. |
| **A. Descarte Total** | **$38{,}0\text{ a }49{,}0\text{ KB/s}$**<br>*(~380 kbps normal)* | **$93{,}0\text{ a }97{,}0\text{ KB/s}$**<br>*(Travou no teto)* | **$9{,}78\text{ ms}$** | **$0\%$** | `h2` foi limitado exatamente aos 100 KB/s da regra. Fila vazia, zero perdas e latência mínima para `h1`. |
| **B. Probabilístico** | **$46{,}0\text{ a }51{,}0\text{ KB/s}$**<br>*(~400 kbps total)* | **$145{,}0\text{ a }171{,}0\text{ KB/s}$**<br>*(~1.3 Mbps)* | **$59{,}90\text{ ms}$** | **$0\%$** | 80% do excesso de `h2` foi descartado. `h1` operou a 100%, com 0% de perda e uso eficiente do link. |

### Principais Conclusões
* **Tempo de detecção:** Quase imediato. Como a janela é de $1\text{ s}$ e `h2` envia a $312\text{ KB/s}$, o switch levou menos de $0{,}35\text{ segundos}$ para atingir os $100\text{ KB}$ e começar a descartar.
* **Trade-off das Estratégias:** 
  * A **Estratégia A** é ideal para aplicações de missão crítica e tempo real (VoIP, jogos, controle de sensores) porque garante o menor atraso possível ($~10\text{ ms}$).
  * A **Estratégia B** é melhor para tráfego comum e downloads, pois aproveita a banda ociosa do link (o enlace operou em $\approx 1.66\text{ Mbps}$ sem sufocar o `h1`).

---

## 5. Organização e Demonstração

* **Estrutura de arquivos limpa:**
  * `anomalias.p4`: código P4 com parser, tabela LPM, registradores e lógica de descarte.
  * `topology.json`: topologia do Mininet com o limitador de banda de $2\text{ Mbps}$.
  * `s1-runtime.json`: regras iniciais de roteamento e estratégia carregadas no BMv2.
  * `test_traffic.py`: script de socket UDP em Python para cliente e servidor.
  * `Makefile`: script padrão para compilar e subir o ambiente.
* **Demonstração rápida:**
  * Mostramos o teste rodando ao vivo: servidor rodando em `h3` via log (`tail -f h3.log`), disparos em segundo plano de `h1` e `h2`.
  * Para trocar a estratégia sem reiniciar a rede inteira, usamos o `simple_switch_CLI` para modificar a regra da tabela dinamicamente, observando a mudança de comportamento no mesmo instante no terminal.