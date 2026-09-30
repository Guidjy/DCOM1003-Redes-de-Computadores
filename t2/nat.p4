#include <core.p4>
#include <v1model.p4>

// definicao dos tipos basicos de dados com o tamanho exato em bits
typedef bit<48> macAddr_t; // endereco MAC de camada 2 (48 bits / 6 bytes)
typedef bit<32> ip4Addr_t; // endereco IPv4 de camada 3 (32 bits / 4 bytes)

// constante de protocolo de rede para saber se o pacote ethernet carrega ipv4 dentro
const bit<16> TYPE_IPV4 = 0x0800;

// identificadores padrao dos protocolos de transporte que vao dentro do ipv4
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

// enderecos ip da rede interna e o ip publico que o roteador/switch usa para falar com a internet
const ip4Addr_t IP_PUBLIC_S1 = 0xC8000001; // ip publico do switch: 200.0.0.1
const ip4Addr_t IP_H1        = 0x0A000001; // ip privado do computador 1: 10.0.0.1
const ip4Addr_t IP_H2        = 0x0A000002; // ip privado do computador 2: 10.0.0.2

// macs associados a conexao da porta 1 (host 1 <-> porta 1 do switch)
const macAddr_t MAC_H1       = 0x080000000101;
const macAddr_t MAC_S1_P1    = 0x080000000103;

// macs associados a conexao da porta 2 (host 2 <-> porta 2 do switch)
const macAddr_t MAC_H2       = 0x080000000202;
const macAddr_t MAC_S1_P2    = 0x080000000204;

// macs associados a conexao da porta 3 externa (host 3 / internet <-> porta 3 do switch)
const macAddr_t MAC_H3       = 0x080000000303;
const macAddr_t MAC_S1_P3    = 0x080000000301;

// ============================================================================
// 1. HEADERS (Estruturas dos cabecalhos dos pacotes)
// ============================================================================

// cabecalho ethernet: responsavel pela entrega local entre placas de rede
header ethernet_t {
    macAddr_t dstAddr;   // mac de destino
    macAddr_t srcAddr;   // mac de origem
    bit<16>   etherType; // tipo de protocolo que vem logo em seguida (ex: ipv4)
}

// cabecalho ipv4: responsavel pelo roteamento entre computadores na internet
header ipv4_t {
    bit<4>    version;        // versao do ip (sempre 4 aqui)
    bit<4>    ihl;            // tamanho do cabecalho ip em blocos de 32 bits
    bit<8>    diffserv;       // tipo de servico / prioridade do pacote
    bit<16>   totalLen;       // tamanho total do pacote em bytes (cabecalho + dados)
    bit<16>   identification; // id usado para remontar pacote se ele for fragmentado
    bit<3>    flags;          // flags de fragmentacao
    bit<13>   fragOffset;     // posicao do pedaco fragmentado
    bit<8>    ttl;            // time to live: contador de saltos para o pacote nao rodar infinito
    bit<8>    protocol;       // diz o que vem dentro (tcp, udp, icmp, etc.)
    bit<16>   hdrChecksum;    // soma de verificacao de erro apenas do cabecalho ip
    ip4Addr_t srcAddr;        // ip de quem enviou
    ip4Addr_t dstAddr;        // ip de quem deve receber
}

// cabecalho tcp: protocolo de transporte confiavel orientado a conexao
header tcp_t {
    bit<16> srcPort;    // porta de saida do programa no computador de origem
    bit<16> dstPort;    // porta do servico no computador de destino (ex: 80 web)
    bit<32> seqNo;      // numero de sequencia para ordenar os dados
    bit<32> ackNo;      // confirmacao dos dados que ja foram recebidos
    bit<4>  dataOffset; // tamanho do cabecalho tcp
    bit<3>  res;        // bits reservados
    bit<3>  ecn;        // notificacao de congestionamento
    bit<6>  ctrl;       // flags de controle (SYN, ACK, FIN, RST, etc.)
    bit<16> window;     // tamanho da janela de recepcao (controle de fluxo)
    bit<16> checksum;   // soma de verificacao do pacote tcp inteiro
    bit<16> urgentPtr;  // ponteiro para dados urgentes
}

// cabecalho udp: protocolo de transporte simples e rapido sem confirmacao
header udp_t {
    bit<16> srcPort;  // porta de origem
    bit<16> dstPort;  // porta de destino
    bit<16> length_;  // tamanho do cabecalho udp + carga de dados
    bit<16> checksum; // soma de verificacao para detectar se pacote corrompeu
}

// agrupa todos os cabecalhos conhecidos que um pacote pode carregar
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

// variaveis internas de controle que viajam com o pacote dentro do switch mas nao vao pra rede
struct metadata {
    bit<16> nat_port;   // porta temporaria usada para consultar a tabela de nat
    bit<16> tcp_length; // tamanho calculado da carga tcp para poder recalcular o checksum
}

// ============================================================================
// 2. PARSER (Decodificador de bytes brutos em cabecalhos legiveis)
// ============================================================================
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // estado inicial: todo pacote recebido comeca sendo tratado como ethernet
    state start {
        transition parse_ethernet;
    }

    // extrai o comeco do pacote como ethernet e olha o ethertype para saber o proximo passo
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4; // se for ipv4 vai decodificar a camada ip
            default: accept;       // se for outro protocolo encerra a analise e aceita o pacote
        }
    }

    // extrai o cabecalho ipv4 e analisa o campo protocolo para saber o transporte
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp; // se for 6 extrai como tcp
            PROTO_UDP: parse_udp; // se for 17 extrai como udp
            default: accept;      // aceita no parser e descarta no Ingress se nao for TCP/UDP
        }
    }

    // extrai os campos do cabecalho tcp e termina o parser
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    // extrai os campos do cabecalho udp e termina o parser
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

// ============================================================================
// 3. CHECKSUM VERIFY (Conferir se o pacote chegou corrompido)
// ============================================================================
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    // vazio: o switch nao esta gastando processamento conferindo se o pacote que chegou veio com erro
    apply { }
}

// ============================================================================
// 4. INGRESS PIPELINE (Logica principal de decisoes de encaminhamento e NAT)
// ============================================================================
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // memoria de estado (registradores) para salvar o mapeamento de volta do NAT
    // cada posicao do vetor eh indexada pelo numero da porta externa usada (ate 65535)
    register<ip4Addr_t>(65536) reg_orig_ip;        // guarda o ip interno original da maquina
    register<bit<16>>(65536)   reg_orig_port;      // guarda a porta original de quem disparou o pacote
    register<bit<1>>(65536)    reg_port_allocated; // flag 1/0 para saber se a porta externa esta ocupada por uma conexao ativa

    // acao de descarte: marca o pacote para ir pro lixo
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // acao de encaminhamento padrao: define porta fisica de saida, troca macs e desconta o ttl
    action forward(bit<9> egress_port, macAddr_t dst_mac, macAddr_t src_mac) {
        standard_metadata.egress_spec = egress_port; // porta fisica do switch por onde o pacote vai sair
        hdr.ethernet.srcAddr = src_mac;              // novo mac de origem (porta do switch)
        hdr.ethernet.dstAddr = dst_mac;              // novo mac de destino (dispositivo que vai receber)
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;             // subtrai 1 da vida do pacote
    }

    // acao de saida da rede local para a internet: troca ip interno pelo publico e lembra quem fez o pedido
    action nat_outbound(bit<16> allocated_ext_port, bit<9> egress_port, macAddr_t dst_mac, macAddr_t src_mac) {
        // salva o ip original na tabela usando a porta externa como chave/indice
        reg_orig_ip.write((bit<32>)allocated_ext_port, hdr.ipv4.srcAddr);

        // descobre a porta original de origem dependendo se o pacote for tcp ou udp e troca pela porta externa
        bit<16> orig_port = 0;
        if (hdr.tcp.isValid()) {
            orig_port = hdr.tcp.srcPort;
            hdr.tcp.srcPort = allocated_ext_port; // mascara a porta tcp
        } else if (hdr.udp.isValid()) {
            orig_port = hdr.udp.srcPort;
            hdr.udp.srcPort = allocated_ext_port; // mascara a porta udp
        }
        
        // guarda a porta de origem real e marca que essa porta externa agora esta ocupada
        reg_orig_port.write((bit<32>)allocated_ext_port, orig_port);
        reg_port_allocated.write((bit<32>)allocated_ext_port, 1);

        // mascara o ip de origem colocando o ip publico do switch
        hdr.ipv4.srcAddr = IP_PUBLIC_S1;

        // envia o pacote mascarado para fora
        forward(egress_port, dst_mac, src_mac);
    }

    // acao de dnat estatico (redirecionamento de portas / port forwarding de fora para dentro)
    action port_forward(ip4Addr_t internal_ip, bit<16> internal_port, bit<9> egress_port, macAddr_t dst_mac, macAddr_t src_mac) {
        // substitui o ip de destino pelo ip do servidor interno correto
        hdr.ipv4.dstAddr = internal_ip;
        
        // ajusta a porta de destino para a porta interna que o servidor escuta
        if (hdr.tcp.isValid()) {
            hdr.tcp.dstPort = internal_port;
        } else if (hdr.udp.isValid()) {
            hdr.udp.dstPort = internal_port;
        }
        // encaminha o pacote para dentro da rede
        forward(egress_port, dst_mac, src_mac);
    }

    // tabela controlada pelo plano de controle para regras de port forwarding estatico
    table static_dnat {
        key = {
            meta.nat_port: exact; // busca uma regra exata baseada na porta de destino que chegou
        }
        actions = {
            port_forward;
            drop;
        }
        size = 1024;
        default_action = drop(); // se nao tiver regra para a porta, descarta
    }
    
    // Acao para reverter o port forwarding: mascara com a porta externa original
    action reverse_port_forward(bit<16> external_port, bit<9> egress_port, macAddr_t dst_mac, macAddr_t src_mac) {
        if (hdr.tcp.isValid()) {
            hdr.tcp.srcPort = external_port;
        } else if (hdr.udp.isValid()) {
            hdr.udp.srcPort = external_port;
        }
        hdr.ipv4.srcAddr = IP_PUBLIC_S1;
        forward(egress_port, dst_mac, src_mac);
    }

    // Tabela estatica para o trafego de retorno do servidor interno
    table static_snat {
        key = {
            hdr.ipv4.srcAddr: exact; // IP do servidor interno (ex: 10.0.0.1)
            meta.nat_port: exact;    // Porta do servidor interno (ex: 80)
        }
        actions = {
            reverse_port_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        // se o pacote nao tiver cabecalho ipv4 valido, joga fora
        if (!hdr.ipv4.isValid()) {
            drop();
            return;
        }

        // descarta ICMP ou qualquer pacote que nao seja TCP nem UDP
        if (!hdr.tcp.isValid() && !hdr.udp.isValid()) {
            drop();
            return;
        }

        // pre-calcula o tamanho para o checksum do TCP sem aritmetica no update_checksum
        // tamanho da carga tcp = tamanho total do ip menos 20 bytes do cabecalho ip fixo
        if (hdr.tcp.isValid()) {
            meta.tcp_length = hdr.ipv4.totalLen - 20;
        }

        // FLUXO DE SAIDA: H1 ou H2 -> H3
        // verifica se o pacote veio de uma das maquinas internas (portas fisicas 1 ou 2)
        // FLUXO DE SAIDA: H1 ou H2 -> H3
        if (standard_metadata.ingress_port == 1 || standard_metadata.ingress_port == 2) {
            bit<16> orig_port = 0;
            if (hdr.tcp.isValid()) {
                orig_port = hdr.tcp.srcPort;
            } else if (hdr.udp.isValid()) {
                orig_port = hdr.udp.srcPort;
            }

            // 1. Verifica se eh uma resposta de um port_forward estatico
            meta.nat_port = orig_port;
            if (!static_snat.apply().hit) {
                
                // 2. Se a tabela estatica der "miss", entao eh trafego dinamico comum
                bit<1> is_busy = 0;
                reg_port_allocated.read(is_busy, (bit<32>)orig_port);

                bit<16> ext_port = orig_port;

                if (is_busy == 1) {
                    ext_port = orig_port + 10000;
                }

                nat_outbound(ext_port, 3, MAC_H3, MAC_S1_P3);
            }
        }

        // FLUXO DE RETORNO: H3 -> H1 ou H2
        // pacote veio da internet / host externo entrando pela porta 3
        else if (standard_metadata.ingress_port == 3) {
            bit<16> lookup_port = 0;
            // le qual foi a porta de destino solicitada
            if (hdr.tcp.isValid()) {
                lookup_port = hdr.tcp.dstPort;
            } else if (hdr.udp.isValid()) {
                lookup_port = hdr.udp.dstPort;
            }

            // confere se essa porta foi alocada dinamicamente pelo nat de saida
            bit<1> is_alloc = 0;
            reg_port_allocated.read(is_alloc, (bit<32>)lookup_port);

            // caso 1: eh resposta de uma conexao que comecou internamente
            if (is_alloc == 1) {
                ip4Addr_t original_ip;
                bit<16> original_port;

                // recupera quem tinha aberto essa conexao la do comeco
                reg_orig_ip.read(original_ip, (bit<32>)lookup_port);
                reg_orig_port.read(original_port, (bit<32>)lookup_port);

                // restaura o ip de destino verdadeiro da maquina interna
                hdr.ipv4.dstAddr = original_ip;

                // restaura a porta de destino interna
                if (hdr.tcp.isValid()) {
                    hdr.tcp.dstPort = original_port;
                } else if (hdr.udp.isValid()) {
                    hdr.udp.dstPort = original_port;
                }

                // decide para qual porta fisica devolver o pacote baseado no ip interno
                if (original_ip == IP_H1) {
                    forward(1, MAC_H1, MAC_S1_P1);
                } else if (original_ip == IP_H2) {
                    forward(2, MAC_H2, MAC_S1_P2);
                } else {
                    drop();
                }
            } 
            // caso 2: nao eh conexao ativa, entao tenta bater na tabela de dnat estatico
            else {
                meta.nat_port = lookup_port;
                static_dnat.apply();
            }
        }
    }
}

// ============================================================================
// 5. EGRESS PIPELINE (Processamento logo antes de colocar o pacote no cabo)
// ============================================================================
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    // nenhuma alteracao especial na saida individual da porta
    apply { }
}

// ============================================================================
// 6. CHECKSUM COMPUTE (Recalcular os checksums modificados pelo NAT)
// ============================================================================
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // recalcula o checksum do cabecalho ipv4 porque alteramos o ip de origem ou destino
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        // recalcula o checksum do tcp incluindo pseudo-cabecalho e a carga de dados (payload)
        update_checksum_with_payload(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                (bit<8>)0,
                hdr.ipv4.protocol,
                meta.tcp_length,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.ctrl,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );

        // recalcula o checksum do udp incluindo pseudo-cabecalho e a carga util
        update_checksum_with_payload(
            hdr.udp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                (bit<8>)0,
                hdr.ipv4.protocol,
                hdr.udp.length_,
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length_
            },
            hdr.udp.checksum,
            HashAlgorithm.csum16
        );
    }
}

// ============================================================================
// 7. DEPARSER (Remontagem dos cabecalhos em bytes brutos para transmissao)
// ============================================================================
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // remonta os cabecalhos em ordem caso eles estejam validos
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

// ============================================================================
// 8. MAIN SWITCH (Instancia final da arquitetura padrao V1Switch)
// ============================================================================
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
