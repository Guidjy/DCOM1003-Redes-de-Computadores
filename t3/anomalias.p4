// Descricao: Pipeline de plano de dados para encaminhamento IPv4, deteccao de anomalias de trafego e mitigacao por fluxo
// Tecnologias: P4_16, Arquitetura V1Model (BMv2)
// Modulo: Processamento de pacotes e controle de sobrecarga no switch

// importa as bibliotecas padrao da linguagem P4 e o modelo de switch V1Model
#include <core.p4>
#include <v1model.p4>

// define a constante hexadecimal correspondente ao protocolo IPv4 no quadro Ethernet
const bit<16> TYPE_IPV4 = 0x800;

// define a janela de tempo de 1 segundo em microssegundos para medicao de trafego
const bit<48> WINDOW_SIZE_US = 1000000;
// define o limite inferior de bytes por janela para classificar anomalia moderada
const bit<32> THRESHOLD_LOW  = 100000;
// define o limite superior de bytes por janela para classificar anomalia severa
const bit<32> THRESHOLD_HIGH = 200000;

// define tipos customizados para a porta de saida e enderecos fisicos e logicos
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// estrutura do cabecalho da camada de enlace Ethernet
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// estrutura do cabecalho da camada de rede IPv4
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// armazena metadados internos do pacote para definir a estrategia de mitigacao
struct metadata {
    bit<2> strategy;
}

// agrupa todos os cabecalhos validos extraidos durante o processamento do pacote
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

// maquina de estados para extracao de cabecalhos dos pacotes recebidos
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // estado inicial que direciona o fluxo para a analise do cabecalho Ethernet
    state start {
        transition parse_ethernet;
    }

    // extrai o cabecalho Ethernet e avanca para IPv4 caso o tipo seja compativel
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    // extrai o cabecalho IPv4 e encerra a leitura de cabecalhos com sucesso
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

// bloco de controle para validacao de checksum na entrada do pipeline
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

// bloco principal de processamento de entrada, roteamento e controle de anomalias
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // aloca registradores no plano de dados para armazenar volume de bytes e tempo por fluxo
    register<bit<32>>(1024) reg_byte_count;
    register<bit<48>>(1024) reg_last_time;

    // marca o pacote atual para descarte imediato no final do pipeline
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // atualiza a porta de saida, os enderecos MAC de origem e destino e reduz o tempo de vida
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // tabela de encaminhamento IPv4 que busca correspondencia pelo prefixo mais longo
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // atribui o identificador da estrategia de mitigacao aos metadados do pacote
    action set_strategy(bit<2> strat) {
        meta.strategy = strat;
    }

    // tabela para consultar a politica de mitigacao configurada para o destino
    table mitigation_config {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_strategy;
        }
        size = 16;
        default_action = set_strategy(0);
    }

    // executa a logica sequencial de encaminhamento, medicao e filtragem de pacotes
    apply {
        // executa as regras apenas se o pacote possuir um cabecalho IPv4 extraido e valido
        if (hdr.ipv4.isValid()) {
            // consulta as tabelas de roteamento e de configuracao de estrategia
            ipv4_lpm.apply();
            mitigation_config.apply();

            // calcula o indice do fluxo de 0 a 1023 aplicando hash CRC16 sobre o IP de origem
            bit<32> flow_idx;
            hash(flow_idx, HashAlgorithm.crc16, (bit<32>)0, { hdr.ipv4.srcAddr }, (bit<32>)1024);

            // le dos registradores a contagem de bytes e o timestamp do ultimo pacote deste fluxo
            bit<32> byte_cnt;
            bit<48> last_time;
            reg_byte_count.read(byte_cnt, flow_idx);
            reg_last_time.read(last_time, flow_idx);

            // captura o tempo atual de entrada do pacote no switch
            bit<48> cur_time = standard_metadata.ingress_global_timestamp;

            // verifica se o tempo decorrido desde o ultimo pacote ultrapassa a janela de 1 segundo
            if (cur_time - last_time > WINDOW_SIZE_US) {
                // reinicia a contagem de bytes e atualiza a referencia de tempo da janela
                byte_cnt = standard_metadata.packet_length;
                last_time = cur_time;
            } else {
                // acumula o tamanho do pacote atual ao volume total da janela vigente
                byte_cnt = byte_cnt + standard_metadata.packet_length;
            }

            // grava nos registradores o volume de bytes e o tempo de referencia atualizados
            reg_byte_count.write(flow_idx, byte_cnt);
            reg_last_time.write(flow_idx, last_time);

            // avalia se o volume acumulado do fluxo ultrapassa o limite minimo de anomalia
            if (byte_cnt > THRESHOLD_LOW) {
                // aplica o descarte total caso a estrategia configurada seja 1
                if (meta.strategy == 1) {
                    // descarta o pacote imediatamente
                    drop();
                // aplica o descarte probabilistico caso a estrategia configurada seja 2
                } else if (meta.strategy == 2) {
                    // gera um numero pseudoaleatorio entre 0 e 99 para decidir o descarte
                    bit<32> rand_val;
                    random<bit<32>>(rand_val, 0, 99);

                    // verifica se o volume de trafego atingiu o nivel de anomalia severa
                    if (byte_cnt > THRESHOLD_HIGH) {
                        // aplica 80 por cento de probabilidade de descarte para trafego severo
                        if (rand_val < 80) {
                            drop();
                        }
                    } else {
                        // aplica 40 por cento de probabilidade de descarte para trafego moderado
                        if (rand_val < 40) {
                            drop();
                        }
                    }
                }
            }
        }
    }
}

// bloco de controle para processamento de pacotes na saida do switch
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

// recalcula o checksum do cabecalho IPv4 apos a alteracao do campo TTL no roteamento
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        // atualiza o valor de verificacao usando o algoritmo padrao de 16 bits sobre os campos IPv4
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// remonta os cabecalhos modificados no buffer de saida antes da transmissao fisica
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // serializa os cabecalhos Ethernet e IPv4 na ordem correta do protocolo
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

// instancia o pipeline completo conectando os blocos ao modelo de switch V1Switch
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;