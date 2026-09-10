// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_ICMP = 0x0001;

/*************************************************************************
*********************** H E A D E R S  ***********************************
* This program skeleton defines minimal Ethernet and IPv4 headers and    *
* a simple LPM (Longest-Prefix Match) IPv4 forwarding pipeline.          *
* The exercise intentionally leaves TODOs for learners to implement.     *
*************************************************************************/

typedef bit<9>  egressSpec_t;   // Standard BMv2 uses 9 bits for egress_spec
typedef bit<48> macAddr_t;      // Ethernet MAC address
typedef bit<32> ip4Addr_t;      // IPv4 address

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

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

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
}

/*************************************************************************
*********************** P A R S E R  *************************************
* New to P4? A typical parser does this:
*   start -> parse_ethernet
*   parse_ethernet:
*       if etherType == TYPE_IPV4 -> parse_ipv4
*       else accept
*   parse_ipv4 -> accept
* This skeleton leaves the actual states as a TODO to implement later.   *
*************************************************************************/

// converte um floxu de bytes em cabeçários de pacotes estruturados
parser MyParser(packet_in packet,     // pacote bruto com um cursor interno para o último bit lido
                out headers hdr,      // estrutura de header definida acima. Inicialmente inválida
                inout metadata meta,   
                inout standard_metadata_t standard_metadata) {

    // ponto de entrada do parser
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);  // lê o número exato de bits definido por ethernet_t, preenche hdr.ethernet, avança o cursor e seta hdr.ethernet.isValid() = true
        transition select(hdr.ethernet.etherType) {  // como se fosse um switch case
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            default: accept;  // poderia rejeitar qualquer pacote que não seja ICMP aqui mas isso será feito no ingress
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
* High-level intent:
*   - Do an LPM lookup on IPv4 dstAddr
*   - On hit, call ipv4_forward(next-hop MAC, output port)
*   - Otherwise, drop or NoAction (as configured)                         *
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Ação que recebe o endereço MAC do dispositivo do próximo hop e a porta do switch pela qual o pacote vai ser transmitido
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        if (hdr.ipv4.ttl <= 1) {
            mark_to_drop(standard_metadata);
            return;
        }

        standard_metadata.egress_spec = port;         // adiciona a porta ed output na metadata do pipeline do switch
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;  // troca o endereço MAC fonte do pacote pelo endereço de destino antigo (próprio endereço do switch)
        hdr.ethernet.dstAddr = dstAddr;               // troca o endereço MAC de destino do pacote pelo endereço passado para a ação
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /*********************************************************************
     * LPM table for IPv4:
     *   - Matches on hdr.ipv4.dstAddr using longest-prefix match (lpm)
     *   - On hit, calls ipv4_forward with *action data* populated by the
     *     control plane when it installs the table entry.
     *********************************************************************/
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
        default_action = NoAction();
    }

    apply {
        // dropa pacotes que não sejam ICMP
        if (!hdr.ipv4.isValid() || !hdr.icmp.isValid()) {
            mark_to_drop(standard_metadata);
            return;
        }

        ipv4_lpm.apply();  // Faz um lookup na tabela ipv4_lpm usando hdr.ipv4.dstAddr como chave. Se der hit, executa ipv4_forward.
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
* Often used for queue marks, mirroring, or post-routing edits.          *
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
* This block shows how to compute IPv4 header checksum when needed.      *
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
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


/*************************************************************************
***********************  D E P A R S E R  *******************************
* The deparser serializes headers back onto the packet in order.         *
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // serializa e faz append dos headers dos protocolos no pacote
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
    }
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
