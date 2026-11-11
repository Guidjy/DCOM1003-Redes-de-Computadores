# Relatório Técnico: Detecção e Tratamento de Anomalias de Tráfego em P4

**Disciplina:** Redes de Computadores / Sistemas de Redes Programáveis  
**Instituição:** Universidade Federal de Santa Maria (UFSM) — Centro de Tecnologia  
**Departamento:** Departamento de Computação Aplicada  
**Docente:** Prof. Carlos Raniery P. dos Santos  
**Alunos:** Enzo Silveira, Guilherme Pimentel, Luan Streck

---

## Resumo

Este relatório descreve o projeto, a implementação e a avaliação empírica de um mecanismo de detecção e mitigação de anomalias de tráfego executado diretamente no plano de dados (*Data Plane*) de um comutador de pacotes programável utilizando a linguagem **P4_16** sob o modelo arquitetural **V1Model**. O comportamento anômalo abordado foi caracterizado como um **Fluxo Elefante / Rajada Excessiva de Tráfego**, no qual um emissor injeta uma taxa de transmissão desproporcional capaz de saturar a capacidade de um enlace compartilhado. 

A solução proposta mantém estado no próprio switch por meio de primitivas de registradores (`register`) e estampas de tempo globais (`ingress_global_timestamp`), calculando a taxa de transferência em janelas temporais deslizantes de $1\text{ s}$ de maneira autônoma, sem intervenção do plano de controle (*Control Plane*). Foram avaliadas e comparadas duas estratégias de tratamento contra um cenário de controle: **Descarte Total (Estratégia A)** e **Descarte Probabilístico Adaptativo (Estratégia B)**. Os experimentos realizados no ambiente emulado **Mininet** com o switch virtual **BMv2** comprovaram a eficácia da abordagem: sob ausência de mitigação, a anomalia gerou colapso na rede com latência de $1809.15\text{ ms}$ e $60\%$ de perda de pacotes para o fluxo legítimo; em contrapartida, as estratégias de mitigação no *Data Plane* estabilizaram o enlace, eliminando perdas e preservando a qualidade de serviço do tráfego legítimo.

---

## 1. Introdução e Contextualização

Em arquiteturas convencionais de Redes Definidas por Software (SDN), a identificação de anomalias e de violações de políticas de tráfego comumente depende de uma abordagem reativa baseada no plano de controle. Nesse paradigma, os switches de encaminhamento realizam amostragens ou geram eventos periódicos em direção a um controlador centralizado, o qual processa os fluxos, diagnostica distúrbios operacionais e injeta novas regras nas tabelas de fluxo. Embora funcional para redes de baixa velocidade, esse modelo centralizado apresenta gargalos estruturais inerentes:
1. **Sobrecarga de Sinalização:** O envio frequente de mensagens de controle (*Packet-In* / estatísticas) satura o canal de gerência;
2. **Latência de Decisão:** O atraso de ida e volta (*Round-Trip Time* — RTT) entre o switch e o controlador impede a contenção de rajadas rápidas e ataques volumétricos nos estágios iniciais;
3. **Escalabilidade Computacional:** A CPU do controlador torna-se um ponto único de estrangulamento quando centenas de fluxos sofrem variações simultâneas.

Com o advento da programabilidade no plano de dados através da linguagem **P4 (Programming Protocol-Independent Packet Processors)**, tornou-se viável transferir tarefas analíticas e de monitoramento com estado (*stateful computing*) para a própria estrutura de encaminhamento em taxas de linha (*wire-speed*). 

Este trabalho tem por finalidade projetar, implementar e validar um sistema autônomo de identificação e contenção de anomalias volumétricas no plano de dados, assegurando proteção contra degradação de serviço em enlaces congestionados.

---

## 2. Definição e Justificativa da Anomalia de Tráfego

### 2.1 Caracterização do Comportamento Anômalo

A anomalia investigada neste trabalho é classificada como **Fluxo Elefante (*Elephant Flow*) em regime de rajada**, caracterizado por um fluxo individual que injeta volume ou taxa contínua de transmissão excessivamente altos em comparação aos demais fluxos concorrentes.

Em ambientes de redes locais ou de centros de dados, fluxos de curta duração e baixa taxa (*Mice Flows*), associados a tráfego de controle, consultas web, chamadas de procedimento remoto (RPC) e voz sobre IP, compartilham enlaces físicos com transferências massivas de arquivos ou fluxos maliciosos (e.g., ataques de negação de serviço volumétricos). Sem um controle granular, fluxos de alta vazão monopolizam os buffers das interfaces de comutação, provocando o fenômeno de **Bufferbloat**, elevação descontrolada de latência e descarte por estouro de fila (*Tail Drop*) sobre fluxos legítimos.

### 2.2 Formalização Matemática e Limiares Operacionais

A verificação do comportamento anômalo fundamenta-se na taxa instantânea de transmissão de bytes recebidos por fluxo $f$ dentro de uma janela temporal finita $\Delta T$.

Seja $L_i$ o tamanho em bytes do $i$-ésimo pacote pertencente ao fluxo $f$, e seja $t_i$ o instante de chegada desse pacote. A taxa observada $R_f(t)$ é expressa por:

$$
R_f(t) = \frac{\sum_{i \in \mathcal{W}_f(t)} L_i}{\Delta T}
$$

Onde $\mathcal{W}_f(t)$ representa o conjunto de pacotes do fluxo $f$ recebidos no intervalo temporal $[t - \Delta T, t]$.

Para a concretização prática no comutador, fixou-se a janela de amostragem em:

$$
\Delta T = 1.000.000\ \mu\text{s} = 1{,}0\text{ segundo}
$$

Definiram-se dois limiares de decisão objetivos com base na capacidade máxima do enlace compartilhado de saída ($C = 2\text{ Mbps} = 250\text{ KB/s}$):

1. **Limiar de Anomalia Moderada ($\text{THRESHOLD\_LOW}$):**
   $$
   \text{THRESHOLD\_LOW} = 100.000\text{ bytes} \implies R_{\text{lim\_low}} = 100\text{ KB/s}\ (800\text{ kbps})
   $$
   *Critério:* Qualquer fluxo individual que consuma mais de $40\%$ da capacidade total do enlace gargalo é classificado como anômalo.

2. **Limiar de Anomalia Severa ($\text{THRESHOLD\_HIGH}$):**
   $$
   \text{THRESHOLD\_HIGH} = 200.000\text{ bytes} \implies R_{\text{lim\_high}} = 200\text{ KB/s}\ (1600\text{ kbps})
   $$
   *Critério:* Fluxos que demandam mais de $80\%$ da capacidade de transmissão da interface, indicando monopólio quase total do recurso e risco imediato de inanição (*starvation*) dos demais usuários.

O tráfego de teste legítimo gerado pelo host $h_1$ foi parametrizado em $R_{h_1} \approx 400\text{ kbps}$ ($50\text{ KB/s}$), permanecendo rigorosamente abaixo do limiar $\text{THRESHOLD\_LOW}$, enquanto o tráfego anômalo gerado por $h_2$ foi configurado em $R_{h_2} \approx 2500\text{ kbps}$ ($312\text{ KB/s}$), violando ambos os limiares.

---

## 3. Arquitetura e Implementação no Data Plane em P4_16

A solução foi desenvolvida no padrão **P4_16** para o alvo **BMv2 (`simple_switch_grpc`)** utilizando a arquitetura padrão **V1Model**. O pipeline de processamento é decomposto em três blocos operacionais essenciais:

```
+---------------+      +-------------------+      +---------------------+      +-----------------+
|   Parser      | ---> |   Ingress Match   | ---> | Ingress State &     | ---> |    Deparser     |
| (Ethernet/IP) |      | (LPM Forwarding)  |      | Rate Anomaly Engine |      | (Packet Egress) |
+---------------+      +-------------------+      +---------------------+      +-----------------+
```

### 3.1 Identificação de Fluxos e Manutenção de Estado

Diferente do plano de controle tradicional, o plano de dados em hardware não dispõe de alocação dinâmica de memória (como tabelas hash redimensionáveis ou árvores de busca). Dessa forma, a retenção de estado entre pacotes foi implementada por meio de arrays de registradores (`register`) de tamanho estático:

```p4
register<bit<32>>(1024) reg_byte_count; // Armazena o total de bytes acumulados
register<bit<48>>(1024) reg_last_time;  // Armazena o timestamp de início da janela
```

Para mapear os pacotes recebidos às suas respectivas posições de estado, utiliza-se a primitiva de cálculo criptográfico/hash sobre o endereço IP de origem (`hdr.ipv4.srcAddr`):

$$
\text{flow\_idx} = \text{hash}_{\text{CRC16}}(\text{hdr.ipv4.srcAddr}) \pmod{1024}
$$

Essa abordagem garante que pacotes de um mesmo remetente acessem consistentemente o mesmo slot de memória, operando com complexidade computacional constante de tempo $O(1)$.

### 3.2 Lógica Temporal da Janela Deslizante

Para viabilizar a medição de taxas de transferência, o switch utiliza o metadado intrínseco fornecido pela arquitetura:

$$
t_{\text{atual}} = \text{standard\_metadata.ingress\_global\_timestamp}
$$

Ao receber um pacote, o comutador lê o instante de tempo em que a janela atual foi iniciada ($t_{\text{último}} = \text{reg\_last\_time}[\text{flow\_idx}]$) e calcula o intervalo decorrido:

$$
\Delta t = t_{\text{atual}} - t_{\text{último}}
$$

A atualização do registrador segue a seguinte máquina de estados no Ingress:

```p4
if (cur_time - last_time > WINDOW_SIZE_US) {
    // A janela anterior (1 segundo) expirou: reinicia o ciclo
    byte_cnt = standard_metadata.packet_length;
    last_time = cur_time;
} else {
    // Pacote recebido dentro da janela corrente: soma o volume
    byte_cnt = byte_cnt + standard_metadata.packet_length;
}

// Atualização atômica dos registradores no switch
reg_byte_count.write(flow_idx, byte_cnt);
reg_last_time.write(flow_idx, last_time);
```

Caso `byte_cnt` ultrapasse $\text{THRESHOLD\_LOW}$, o switch ativa automaticamente as ações de mitigação sem requerer comunicação externa.

---

## 4. Estratégias de Tratamento de Anomalias

Para cumprir as diretrizes metodológicas do projeto, o comutador foi estruturado para suportar políticas distintas de mitigação, controladas através da tabela `mitigation_config`.

### 4.1 Cenário 0: Ausência de Mitigação (`strat = 0`)
Atua como grupo de controle experimental. O switch executa estritamente o encaminhamento IPv4 por casamento do prefixo de destino (*Longest Prefix Match* — LPM). Todos os pacotes são colocados na fila de saída da porta de destino, expondo as vulnerabilidades do compartilhamento não gerenciado do enlace gargalo.

### 4.2 Estratégia A: Descarte Total (`strat = 1`)
A política de descarte determinístico opera interrompendo integralmente o encaminhamento do tráfego excedente daquele emissor na janela ativa.

* **Regra de Ação:**
  $$
  \text{Se } \text{byte\_cnt} > \text{THRESHOLD\_LOW} \implies \text{mark\_to\_drop}(\text{standard\_metadata})
  $$
* **Comportamento Esperado:** Assim que a soma acumulada de um host atinge $100\text{ KB}$, todos os pacotes posteriores daquele mesmo host são descartados na camada de Ingress até que a janela de $1\text{ segundo}$ expire e o contador seja reiniciado.
* **Vantagem:** Esvaziamento instantâneo da fila do switch, eliminação total do *bufferbloat* e garantia de vazão integral e latência mínima para os fluxos legítimos.

### 4.3 Estratégia B: Descarte Probabilístico Adaptativo (`strat = 2`)
A segunda política introduz uma atenuação proporcional à gravidade da anomalia, permitindo degradação graciosa da taxa de transferência em vez de um corte abrupto.

Para isso, utiliza-se a primitiva de aleatoriedade no hardware:
```p4
bit<32> rand_val;
random<bit<32>>(rand_val, 0, 99); // Gera número pseudoaleatório entre 0 e 99
```

A probabilidade de descarte $P(\text{Drop})$ é mapeada de forma estocástica e escalonada:

$$
P(\text{Drop}) = 
\begin{cases} 
0\%, & \text{se } \text{byte\_cnt} \le \text{THRESHOLD\_LOW} \\
40\%, & \text{se } \text{THRESHOLD\_LOW} < \text{byte\_cnt} \le \text{THRESHOLD\_HIGH} \quad (\text{rand\_val} < 40) \\
80\%, & \text{se } \text{byte\_cnt} > \text{THRESHOLD\_HIGH} \quad (\text{rand\_val} < 80)
\end{cases}
$$

* **Comportamento Esperado:** Ao ultrapassar a taxa de $100\text{ KB/s}$, o switch descarta aleatoriamente $40\%$ dos pacotes do fluxo. Caso a agressividade persista e o fluxo supere $200\text{ KB/s}$, a penalidade escala automaticamente para $80\%$ de perda induzida.
* **Vantagem:** Otimização da eficiência do enlace de comunicação. A anomalia é contida para patamares seguros sem interromper o serviço, aproveitando a capacidade ociosa residual do enlace compartilhado.

---

## 5. Metodologia Experimental e Ambiente de Testes

### 5.1 Topologia de Rede Emulada

O ambiente de experimentação foi modelado no **Mininet** com integração à infraestrutura padrão dos tutoriais P4, consistindo na seguinte topologia:

```
[ Host h1: 10.0.1.1 ] --- (10 Mbps) ---+
                                       |
                                    [ Switch s1 ] === (2 Mbps Gargalo) ===> [ Host h3: 10.0.3.3 ]
                                       |
[ Host h2: 10.0.2.2 ] --- (10 Mbps) ---+
```

* **Hosts Emissores:**
  * Host $h_1$: Conectado à interface `s1-eth1` com banda nominal de $10\text{ Mbps}$.
  * Host $h_2$: Conectado à interface `s1-eth2` com banda nominal de $10\text{ Mbps}$.
* **Servidor Receptor:**
  * Host $h_3$: Conectado à interface `s1-eth3`.
* **Gargalo Intencional:**
  * O enlace entre `s1-eth3` e `h3` foi configurado explicitamente no arquivo de topologia (`topology.json`) com largura de banda restrita a **$2\text{ Mbps}$** e latência de propagação de $0\text{ ms}$, evidenciando o ponto crítico de contenção.

### 5.2 Ferramental de Geração e Medição de Tráfego

Para afastar distorções causadas por controle de congestionamento fim-a-fim da camada de transporte (como o mecanismo de retrocesso em janela deslizante do TCP), optou-se pela geração de tráfego **UDP bruto** com datagramas de payload de $1000\text{ bytes}$.

Desenvolveu-se uma aplicação cliente-servidor em Python (`test_traffic.py`):
1. **Servidor ($h_3$):** Escuta a porta UDP 5001 e agrega continuamente o volume total de bytes recebidos de cada endereço IP de origem, imprimindo no console a taxa de vazão (*throughput*) apurada a cada intervalo exato de $1{,}0\text{ segundo}$.
2. **Clientes ($h_1$ e $h_2$):** Injetam pacotes em intervalos de tempo estritamente cronometrados ($I = \frac{L \times 8}{R}$). A execução foi parametrizada com o interpretador em modo não-bufferizado (`python3 -u`) para impedir retenção de dados em memória.
3. **Medição de Latência e Perda:** Durante a execução concorrente dos fluxos UDP, disparou-se a partir de $h_1$ uma sequência periódica de sondas ICMP (*Echo Requests* via utilitário `ping`) direcionadas a $h_3$, mensurando o atraso fim-a-fim ($RTT_{\text{avg}}$) e o percentual de pacotes descartados.

---

## 6. Resultados Experimentais e Discussão

Os testes foram executados de forma sequencial sob condições operacionais idênticas em todos os cenários. A tabela a seguir sintetiza os dados numéricos obtidos durante o regime permanente de operação dos fluxos:

### 6.1 Tabela Comparativa de Resultados

| Métrica / Parâmetro | Cenário 0: Sem Mitigação (`strat = 0`) | Estratégia A: Descarte Total (`strat = 1`) | Estratégia B: Probabilístico (`strat = 2`) |
| :--- | :---: | :---: | :---: |
| **Taxa Injetada $h_1$ (Normal)** | $\approx 400\text{ kbps}$ ($50\text{ KB/s}$) | $\approx 400\text{ kbps}$ ($50\text{ KB/s}$) | $\approx 400\text{ kbps}$ ($50\text{ KB/s}$) |
| **Taxa Injetada $h_2$ (Anômalo)**| $\approx 2500\text{ kbps}$ ($312\text{ KB/s}$) | $\approx 2500\text{ kbps}$ ($312\text{ KB/s}$) | $\approx 2500\text{ kbps}$ ($312\text{ KB/s}$) |
| **Vazão Recebida $h_1$ em $h_3$** | **$6{,}0\text{ a }39{,}0\text{ KB/s}$**<br>($48{,}0\text{ a }312{,}0\text{ kbps}$) | **$38{,}0\text{ a }49{,}0\text{ KB/s}$**<br>($304{,}0\text{ a }392{,}0\text{ kbps}$) | **$46{,}0\text{ a }51{,}0\text{ KB/s}$**<br>($368{,}0\text{ a }408{,}0\text{ kbps}$) |
| **Vazão Recebida $h_2$ em $h_3$** | **$187{,}0\text{ a }241{,}0\text{ KB/s}$**<br>($1496{,}0\text{ a }1928{,}0\text{ kbps}$) | **$93{,}0\text{ a }97{,}0\text{ KB/s}$**<br>($744{,}0\text{ a }776{,}0\text{ kbps}$) | **$145{,}0\text{ a }171{,}0\text{ KB/s}$**<br>($1160{,}0\text{ a }1368{,}0\text{ kbps}$) |
| **Latência Média ($RTT_{\text{avg}}$)** | **$1809{,}15\text{ ms}$** | **$9{,}78\text{ ms}$** | **$59{,}90\text{ ms}$** |
| **Latência Máxima ($RTT_{\text{max}}$)** | **$1809{,}53\text{ ms}$** | **$19{,}32\text{ ms}$** | **$69{,}29\text{ ms}$** |
| **Taxa de Perda de Pacotes ($h_1$)** | **$60{,}0\%$** | **$0{,}0\%$** | **$0{,}0\%$** |
| **Estado do Enlace Gargalo** | Colapso por sobrecarga e inanição | Limitação rígida; buffer ocioso | Uso balanceado; buffer sob controle |

---

### 6.2 Análise Crítica dos Cenários

#### Cenário 0: Saturação Sem Mitigação
Quando o switch opera de forma agnóstica às taxas de transmissão, o comportamento agressivo de $h_2$ satura a fila da interface de saída. Uma vez que o enlace suporta apenas $250\text{ KB/s}$, o fluxo anômalo consumiu entre $75\%$ e $96\%$ de toda a infraestrutura física ($187\text{ a }241\text{ KB/s}$).

Como consequência, os pacotes legítimos de $h_1$ encontraram a fila constantemente lotada, sendo descartados de forma indiscriminada na cauda da fila (*tail drop*), ocasionando **$60\%$ de perda de pacotes**. Os poucos datagramas de $h_1$ que conseguiram ser transmitidos permaneceram represados no buffer durante todo o tempo de transmissão dos pacotes de $h_2$, elevando o RTT de $9{,}7\text{ ms}$ para **$1809{,}15\text{ ms}$** (um aumento de aproximadamente $185$ vezes). Esse resultado evidencia a falha dos sistemas tradicionais desprovidos de inteligência de proteção no plano de dados.

#### Cenário 1: Descarte Total (Estratégia A)
Com a ativação da Estratégia A, o detector P4 identificou que $h_2$ superou o limite de $100\text{ KB/s}$ logo no início da janela temporal. A partir desse instante, a ação `drop()` passou a atuar sumariamente sobre os pacotes subsequentes do host infrator.

A vazão medida de $h_2$ em $h_3$ estabilizou com precisão no patamar de **$93\text{ a }97\text{ KB/s}$** ($\approx 760\text{ kbps}$), o que corresponde rigorosamente ao teto de $100.000\text{ bytes}$ por segundo admitido pelo limiar $\text{THRESHOLD\_LOW}$. Isso impediu que a fila da porta `s1-eth3` enchesse. Como resultado direto, $h_1$ operou com sua vazão esperada ($\approx 384\text{ kbps}$), com **perda nula ($0\%$)** e latência basal de **$9{,}78\text{ ms}$**. O descarte total provou ser um método de isolamento rígido, ideal para assegurar conformidade estrita de Acordo de Nível de Serviço (SLA).

#### Cenário 2: Descarte Probabilístico Adaptativo (Estratégia B)
Ao aplicar a Estratégia B, o switch permitiu que $h_2$ transmitisse além do limiar base de $100\text{ KB/s}$, porém aplicando uma taxa de atenuação estocástica. Como $h_2$ tentava transmitir a $2500\text{ kbps}$ (ultrapassando inclusive o $\text{THRESHOLD\_HIGH}$ de $200\text{ KB/s}$), o motor P4 submeteu o fluxo a $80\%$ de probabilidade de descarte aleatório.

A taxa observada de $h_2$ estabilizou na faixa de **$145\text{ a }171\text{ KB/s}$** ($\approx 1{,}16\text{ a }1{,}36\text{ Mbps}$). Ao mesmo tempo, $h_1$ não apenas manteve **$0\%$ de perda**, como atingiu sua vazão plena de projeto (**$46\text{ a }51\text{ KB/s}$** / $\approx 400\text{ kbps}$). 

A latência média observada no ping foi de **$59{,}90\text{ ms}$**. Embora superior aos $9{,}78\text{ ms}$ da Estratégia A devido à maior ocupação média dos buffers, esse valor é plenamente aceitável e infinitamente inferior aos $1809\text{ ms}$ do cenário sem mitigação. A grande vantagem observada na Estratégia B é a **eficiência de utilização do enlace**: a soma das vazões recebidas de $h_1$ ($~48\text{ KB/s}$) e $h_2$ ($~160\text{ KB/s}$) alcançou cerca de $208\text{ KB/s}$ ($\approx 1{,}66\text{ Mbps}$), ocupando mais de $83\%$ da banda do gargalo de forma estável, sem provocar inanição nem perda no tráfego legítimo.

---

### 6.3 Comparativo e Trade-offs Arquiteturais

A experimentação demonstrou que não existe uma estratégia universalmente superior; a escolha ótima depende dos requisitos da aplicação e da política de engenharia de tráfego:

* **Descarte Total (Estratégia A):**
  * *Vantagens:* Garantia absoluta de atraso mínimo e previsibilidade temporal; blindagem imediata de filas; proteção de fluxos ultra-sensíveis a jitter e latência.
  * *Desvantagens:* Subutilização da capacidade residual do enlace; interrupção abrupta da transferência do fluxo penalizado.
  * *Casos de Uso Recomendados:* Tráfego de controle industrial, telemetria em tempo real, sistemas de automação veicular e redes financeiras de alta frequência.

* **Descarte Probabilístico (Estratégia B):**
  * *Vantagens:* Maximização do throughput global; degradação graciosa do fluxo volumétrico sem quebra de conexão; absorção suave de surtos transitórios.
  * *Desvantagens:* Pequeno acréscimo no RTT médio decorrente da presença controlada de pacotes excedentes no buffer.
  * *Casos de Uso Recomendados:* Redes de distribuição de conteúdo (CDN), tráfego web geral, transferências de dados corporativas em nuvem e fluxos elásticos suportados por TCP.

---

## 7. Conclusões e Considerações Finais

O presente trabalho atingiu com êxito todos os objetivos especificados para o projeto. Através da linguagem P4_16, foi demonstrada a viabilidade prática de conceber, diretamente no plano de dados de comutadores programáveis, mecanismos autônomos de detecção e contenção de anomalias volumétricas baseados em estado.

O emprego de registradores em conjunto com a leitura de metadados temporais intrínsecos (`ingress_global_timestamp`) viabilizou a construção de um detector de janela deslizante capaz de identificar fluxos elefantes em tempo de linha, com tempo de reação inferior a um segundo. A ausência de sinalização para o plano de controle eliminou atrasos de comunicação e sobrecarga de CPU, provando a resiliência da arquitetura contra surtos de congestionamento.

Por fim, a comparação quantitativa entre o **Descarte Total** e o **Descarte Probabilístico** permitiu compreender os compromissos operacionais (*trade-offs*) entre preservação rigorosa de latência e maximização da vazão agregada do canal, consolidando o papel da computação em rede (*In-Network Computing*) como ferramenta fundamental para a evolução da segurança e do desempenho de infraestruturas de telecomunicações modernas.

---

## 8. Referências Bibliográficas

1. BOSSHART, P. et al. P4: Programming protocol-independent packet processors. *ACM SIGCOMM Computer Communication Review*, v. 44, n. 3, p. 87-95, 2014.
2. THE P4 LANGUAGE CONSORTIUM. *P4_16 Language Specification*, version 1.2.3, 2022. Disponível em: <https://p4.org/p4-spec/docs/P4-16-v1.2.3.html>.
3. NIKRAVESH, A. et al. An In-Network Approach for High-Speed Anomaly Detection and Mitigation in P4 Switches. *IEEE Transactions on Network and Service Management*, v. 18, n. 4, p. 4310-4322, 2021.
4. LANTZ, B.; HELLER, B.; MCKEOWN, N. A network in a laptop: rapid prototyping for software-defined networks. In: *ACM SIGCOMM Workshop on Hot Topics in Networks (HotNets)*, 2010.
5. GETTYS, J.; NICHOLS, K. Bufferbloat: Dark buffers in the Internet. *Communications of the ACM*, v. 55, n. 1, p. 57-65, 2012.